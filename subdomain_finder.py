"""
Subdomain Finder Tool  —  SDF v1.0
DNS Enumeration & Subdomain Discovery

Author   : Baibav
Student ID: [Your ID]
Module   : ST4017CMD — Introduction to Programming
College  : Softwarica College of IT & E-Commerce / Coventry University
Date     : February 2026
"""

import socket
import sys
import threading
import time
import os
import queue
from datetime import datetime


# ============================================================
# ANSI Colour Support  —  Kali Linux Terminal Theme
# ============================================================

try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    pass

RST  = '\033[0m'
BOLD = '\033[1m'
DIM  = '\033[2m'
G    = '\033[92m'    # bright green   — found / success / Kali accent
C    = '\033[96m'    # bright cyan    — info / scan status
Y    = '\033[93m'    # yellow         — banner highlight
R    = '\033[91m'    # bright red     — warning / error
P    = '\033[95m'    # magenta        — user prompt / choice
W    = '\033[97m'    # bright white   — borders / normal output
DG   = '\033[32m'    # dark green     — secondary green


def _c(color, text):
    """Wrap *text* in an ANSI escape sequence and reset."""
    return f"{color}{text}{RST}"


# ============================================================
# Custom Data Structure: Node  (used by LinkedList)
# ============================================================

class _Node:
    """
    Singly-linked list node.

    Attributes:
        data: Value stored in this node.
        next (_Node): Pointer to the next node.
    """

    def __init__(self, data):
        self.data = data
        self.next = None


# ============================================================
# Custom Data Structure: LinkedList
# ============================================================

class LinkedList:
    """
    Custom singly linked list for storing discovered subdomains.

    Provides O(1) append (tail pointer) and O(n) iteration.
    Chosen over a plain Python list so that the data structure
    is custom-defined as required by the assessment criteria.
    """

    def __init__(self):
        self._head = None
        self._tail = None
        self._size = 0

    def append(self, data):
        """
        Append data to the tail of the list in O(1).

        Args:
            data: Value to store.
        """
        node = _Node(data)
        if self._tail is None:
            self._head = self._tail = node
        else:
            self._tail.next = node
            self._tail = node
        self._size += 1

    def to_list(self):
        """
        Convert linked list to a Python list.

        Returns:
            list: All stored values in insertion order.
        """
        result = []
        current = self._head
        while current is not None:
            result.append(current.data)
            current = current.next
        return result

    def __len__(self):
        return self._size

    def __iter__(self):
        current = self._head
        while current is not None:
            yield current.data
            current = current.next


# ============================================================
# Custom Data Structure: HashSet
# ============================================================

class HashSet:
    """
    Custom hash set using separate chaining for collision resolution.

    Provides O(1) average-case insertion and membership testing.
    Used to prevent duplicate subdomain entries during concurrent scans.

    Uses the djb2 algorithm for hashing:
        hash = 5381
        for each character c: hash = hash * 33 + ord(c)
    """

    def __init__(self, capacity=2048):
        """
        Initialise the hash set.

        Args:
            capacity (int): Number of buckets (default 2048).
        """
        self._capacity = capacity
        self._buckets = [[] for _ in range(capacity)]
        self._size = 0

    def _hash(self, key):
        """
        djb2 hash function.

        Args:
            key (str): String to hash.

        Returns:
            int: Bucket index in [0, capacity).
        """
        h = 5381
        for ch in key:
            h = ((h << 5) + h) + ord(ch)
        return h % self._capacity

    def add(self, key):
        """
        Add key to the set if not already present.

        Args:
            key (str): Key to add.

        Returns:
            bool: True if newly inserted, False if already present.
        """
        idx = self._hash(key)
        bucket = self._buckets[idx]
        for item in bucket:
            if item == key:
                return False
        bucket.append(key)
        self._size += 1
        return True

    def contains(self, key):
        """
        Test membership in O(1) average case.

        Args:
            key (str): Key to search for.

        Returns:
            bool: True if key exists in the set.
        """
        idx = self._hash(key)
        for item in self._buckets[idx]:
            if item == key:
                return True
        return False

    def __len__(self):
        return self._size


# ============================================================
# Wordlist Generator
# ============================================================

class WordlistGenerator:
    """
    Generates subdomain wordlists from built-in common names
    and optional user-supplied entries.

    Uses a HashSet internally to eliminate duplicates in O(1)
    per entry rather than O(n) list scanning.
    """

    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'pop3', 'imap',
        'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
        'api', 'api2', 'v1', 'v2', 'rest',
        'admin', 'administrator', 'panel', 'cpanel', 'whm',
        'dev', 'development', 'staging', 'test', 'testing',
        'qa', 'uat', 'prod', 'production', 'sandbox',
        'vpn', 'remote', 'rdp', 'ssh', 'gateway',
        'cdn', 'static', 'assets', 'media', 'images', 'img',
        'blog', 'news', 'forum', 'wiki', 'docs', 'help', 'kb',
        'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
        'app', 'mobile', 'm', 'wap', 'webapp',
        'support', 'service', 'ticket', 'helpdesk',
        'webmail', 'mail2', 'mx', 'mx1', 'mx2', 'relay',
        'portal', 'dashboard', 'login', 'auth', 'sso', 'oauth',
        'git', 'gitlab', 'bitbucket', 'svn', 'repo',
        'jenkins', 'ci', 'cd', 'build', 'deploy', 'pipeline',
        'jira', 'confluence', 'redmine', 'tracker',
        'intranet', 'internal', 'extranet', 'private', 'corp',
        'beta', 'alpha', 'demo', 'preview', 'lab',
        'lb', 'load', 'proxy', 'reverse', 'haproxy',
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
        'elastic', 'kibana', 'grafana', 'prometheus', 'influx',
        'files', 'upload', 'download', 'backup', 'archive',
        'status', 'monitor', 'logs', 'logging', 'analytics',
        'secure', 'ssl', 'www2', 'www3', 'server', 'host',
        'cloud', 'k8s', 'kubernetes', 'docker', 'registry',
        'vault', 'secrets', 'config', 'crm', 'erp',
        'autodiscover', 'autoconfig', 'webdav', 'caldav',
        'affiliate', 'partner', 'reseller', 'agent',
        'video', 'stream', 'live', 'rtmp', 'media2',
        'smtp2', 'mail3', 'bounce', 'newsletter', 'campaign',
    ]

    def generate(self, include_custom=None):
        """
        Build a deduplicated wordlist.

        Args:
            include_custom (list | None): Extra subdomain words to append.

        Returns:
            list: Merged, deduplicated wordlist.
        """
        seen = HashSet(capacity=512)
        result = []
        for word in self.COMMON_SUBDOMAINS:
            if seen.add(word):
                result.append(word)
        if include_custom:
            for word in include_custom:
                word = word.strip().lower()
                if word and seen.add(word):
                    result.append(word)
        return result


# ============================================================
# Subdomain Finder  (Core Engine)
# ============================================================

class SubdomainFinder:
    """
    Core subdomain enumeration engine.

    Uses threading and DNS resolution to discover live subdomains.
    Integrates wildcard detection to suppress false positives.

    Attributes:
        domain (str): Target domain.
        found (LinkedList): Confirmed subdomains as (fqdn, ip_list) tuples.
        total_checked (int): Total wordlist entries tested.
        wildcard_ips (set): IPs returned by wildcard DNS (if any).
    """

    def __init__(self, domain, timeout=2):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.found = LinkedList()
        self._seen = HashSet()
        self._lock = threading.Lock()
        self.total_checked = 0
        self.wildcard_ips = set()
        self.start_time = None

    def detect_wildcard(self):
        """
        Detect wildcard DNS by resolving a randomly-named non-existent subdomain.

        Returns:
            bool: True if wildcard DNS is active.
        """
        test_sub = f"zz9randominvalid99xq.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            infos = socket.getaddrinfo(test_sub, None)
            for info in infos:
                self.wildcard_ips.add(info[4][0])
            return True
        except (socket.gaierror, socket.herror, OSError):
            return False

    def resolve_subdomain(self, word):
        """
        Attempt to resolve <word>.<domain> via DNS.

        Filters results that match known wildcard IPs.

        Args:
            word (str): Subdomain prefix to test.

        Returns:
            tuple | None: (fqdn, ip_list) if the subdomain resolves
                          to a non-wildcard address, else None.
        """
        fqdn = f"{word}.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            infos = socket.getaddrinfo(fqdn, None)
            ips = list({info[4][0] for info in infos})
            if self.wildcard_ips:
                filtered = [ip for ip in ips if ip not in self.wildcard_ips]
                if not filtered:
                    return None
                ips = filtered
            return (fqdn, ips)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _worker(self, task_queue):
        """
        Thread worker: pull tasks from queue and resolve each subdomain.

        Args:
            task_queue (queue.Queue): Shared work queue of subdomain words.
        """
        while True:
            try:
                word = task_queue.get_nowait()
            except queue.Empty:
                break
            result = self.resolve_subdomain(word)
            with self._lock:
                self.total_checked += 1
            if result:
                fqdn, ips = result
                with self._lock:
                    if self._seen.add(fqdn):
                        self.found.append((fqdn, ips))
                        ip_str = ', '.join(ips)
                        print(f"  {_c(G, '[+]')} {_c(G, BOLD + 'Found')} : "
                              f"{_c(C, fqdn):<55} {_c(Y, '->')} {_c(G, ip_str)}")
            task_queue.task_done()

    def scan_wordlist(self, wordlist, num_threads=20):
        """
        Enumerate subdomains from wordlist using multi-threaded DNS resolution.

        Args:
            wordlist (list): Subdomain prefixes to test.
            num_threads (int): Number of concurrent DNS threads.
        """
        self.start_time = datetime.now()
        _sep()
        print(f"  {_c(C, '[*]')} Target domain    : {_c(G, BOLD + self.domain)}")
        print(f"  {_c(C, '[*]')} Wordlist size    : {_c(W, str(len(wordlist)))} entries")
        print(f"  {_c(C, '[*]')} Threads          : {_c(W, str(num_threads))}")
        print(f"  {_c(C, '[*]')} Scan started     : {_c(W, self.start_time.strftime('%Y-%m-%d %H:%M:%S'))}")

        print(f"\n  {_c(C, '[*]')} Checking for wildcard DNS...")
        if self.detect_wildcard():
            print(f"  {_c(R, '[!]')} {_c(R, BOLD + 'Wildcard DNS detected!')}")
            print(f"  {_c(R, '[!]')} Wildcard IPs : {_c(Y, ', '.join(self.wildcard_ips))}")
            print(f"  {_c(R, '[!]')} False positives will be filtered automatically.")
        else:
            print(f"  {_c(G, '[+]')} No wildcard DNS detected. Proceeding with scan.")

        print(f"\n  {_c(C, '[*]')} Enumerating subdomains...\n")

        task_queue = queue.Queue()
        for word in wordlist:
            task_queue.put(word)

        threads = []
        for _ in range(min(num_threads, len(wordlist))):
            t = threading.Thread(target=self._worker, args=(task_queue,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        elapsed = (datetime.now() - self.start_time).total_seconds()
        print()
        _sep()
        print(f"  {_c(C, '[*]')} Scan completed in {_c(Y, f'{elapsed:.2f} seconds')}")
        print(f"  {_c(C, '[*]')} Checked   : {_c(W, str(self.total_checked))} subdomains")
        print(f"  {_c(G, '[*]')} Found     : {_c(G, BOLD + str(len(self.found)))} valid subdomains")
        _sep()

    def save_results(self, filename=None):
        """
        Export discovered subdomains to a plain-text file.

        Args:
            filename (str | None): Output filename (auto-generated if None).

        Returns:
            str: Path of the saved file.
        """
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"subdomains_{self.domain}_{ts}.txt"
        results = self.found.to_list()
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("  Subdomain Finder Tool — SDF v1.0 — Results\n")
            f.write("=" * 60 + "\n")
            f.write(f"  Domain  : {self.domain}\n")
            f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Found   : {len(results)} subdomains\n")
            f.write("=" * 60 + "\n\n")
            for fqdn, ips in results:
                f.write(f"  {fqdn:<50} {', '.join(ips)}\n")
        return filename


# ============================================================
# Reverse DNS Lookup
# ============================================================

class ReverseDNSLookup:
    """
    Perform reverse DNS (PTR) lookups on IP addresses.

    Results are stored in a custom LinkedList.
    """

    def __init__(self):
        self.results = LinkedList()

    def lookup(self, ip_address):
        """
        Resolve an IP address to its hostname.

        Args:
            ip_address (str): IP address to reverse-lookup.

        Returns:
            str | None: Hostname if a PTR record exists, else None.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def bulk_lookup(self, ip_list):
        """
        Perform bulk reverse DNS lookups and print results.

        Args:
            ip_list (list): IP addresses to look up.
        """
        print(f"\n  {_c(C, '[*]')} Performing reverse DNS lookups on "
              f"{_c(W, str(len(ip_list)))} address(es)...")
        _sep()
        for ip in ip_list:
            hostname = self.lookup(ip)
            if hostname:
                print(f"  {_c(G, '[+]')} {_c(Y, ip):<28} {_c(W, '->')} {_c(G, hostname)}")
                self.results.append((ip, hostname))
            else:
                print(f"  {_c(DIM, '[-]')} {_c(DIM, ip):<28} {_c(DIM, '-> No PTR record found')}")
        _sep()
        print(f"  {_c(C, '[*]')} Reverse lookup completed. "
              f"Found {_c(G, BOLD + str(len(self.results)))} PTR records.")


# ============================================================
# DNS Record Enumerator
# ============================================================

class DNSEnumerator:
    """
    Enumerate various DNS record types for a given domain.

    Uses standard socket calls for A and AAAA records, and
    probes common mail subdomains to infer MX configuration.
    """

    def __init__(self, domain):
        self.domain = domain.lower().strip()
        self.records = {}

    def get_a_records(self):
        """
        Retrieve A records (IPv4) for the domain.

        Returns:
            list: Unique IPv4 addresses.
        """
        try:
            infos = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    def get_aaaa_records(self):
        """
        Retrieve AAAA records (IPv6) for the domain.

        Returns:
            list: Unique IPv6 addresses.
        """
        try:
            infos = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            return list({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    def get_mx_candidates(self):
        """
        Probe common mail-related subdomains to infer MX hosts.

        Returns:
            list: Hostnames that resolved successfully.
        """
        mail_subs = ['mail', 'smtp', 'mx', 'mx1', 'mx2', 'relay', 'mailserver', 'webmail']
        found = []
        for sub in mail_subs:
            fqdn = f"{sub}.{self.domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.getaddrinfo(fqdn, None)
                found.append(fqdn)
            except socket.gaierror:
                pass
        return found

    def enumerate_all(self):
        """Run full DNS enumeration and display results to stdout."""
        print(f"\n  {_c(C, '[*]')} DNS Enumeration for: {_c(G, BOLD + self.domain)}")
        print(f"  {_c(C, '[*]')} Started at: {_c(W, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
        _sep()

        a_recs = self.get_a_records()
        if a_recs:
            print(f"\n  {_c(Y, BOLD + '[A Records — IPv4 Addresses]')}")
            for ip in a_recs:
                print(f"    {_c(G, '[+]')} {_c(C, self.domain):<42} {_c(W, '->')} {_c(G, ip)}")
        else:
            print(f"\n  {_c(DIM, '[-]')} No A records found for {self.domain}")

        aaaa_recs = self.get_aaaa_records()
        if aaaa_recs:
            print(f"\n  {_c(Y, BOLD + '[AAAA Records — IPv6 Addresses]')}")
            for ip in aaaa_recs:
                print(f"    {_c(G, '[+]')} {_c(C, self.domain):<42} {_c(W, '->')} {_c(G, ip)}")
        else:
            print(f"\n  {_c(DIM, '[-]')} No AAAA records found for {self.domain}")

        mx_recs = self.get_mx_candidates()
        if mx_recs:
            print(f"\n  {_c(Y, BOLD + '[Mail-Related Hosts (MX Candidates)]')}")
            for host in mx_recs:
                print(f"    {_c(G, '[+]')} {_c(G, host)}")
        else:
            print(f"\n  {_c(DIM, '[-]')} No mail-related hosts found")

        print()
        _sep()
        print(f"  {_c(C, '[*]')} DNS enumeration completed")


# ============================================================
# CLI Helpers
# ============================================================

def _sep(char='─', width=58):
    """Print a horizontal separator line."""
    print(f"  {_c(DG, char * width)}")


def _kali_prompt():
    """Return a Kali Linux-style coloured prompt string."""
    return (f"{_c(G, BOLD + '┌──(')}{'baibav' + _c(G, BOLD + '㉿') + 'kali'}"
            f"{_c(G, BOLD + ')-[')}{_c(W, '~')}{_c(G, BOLD + ']')}\n"
            f"{_c(G, BOLD + '└─')}$ ")


def display_banner():
    """Display Kali-Linux-themed application startup banner."""
    os.system('cls' if os.name == 'nt' else 'clear')
    sdf = f"""
{G}{BOLD}  ███████╗██████╗ ███████╗{RST}
{G}{BOLD}  ██╔════╝██╔══██╗██╔════╝{RST}
{G}{BOLD}  ███████╗██║  ██║█████╗  {RST}
{G}{BOLD}  ╚════██║██║  ██║██╔══╝  {RST}
{G}{BOLD}  ███████║██████╔╝██║     {RST}
{G}{BOLD}  ╚══════╝╚═════╝ ╚═╝     {RST}
"""
    print(sdf)
    print(f"  {G}{BOLD}SUBDOMAIN FINDER TOOL{RST}  {DG}v1.0{RST}")
    print(f"  {C}DNS Enumeration & Subdomain Discovery{RST}")
    print(f"  {DIM}Module : ST4017CMD  |  Softwarica / Coventry University{RST}")
    print()


def display_menu():
    """Display Kali-themed main navigation menu."""
    border = _c(G, '─' * 46)
    print(f"  {_c(G, '┌' + '─' * 46 + '┐')}")
    print(f"  {_c(G, '│')}  {_c(Y, BOLD + 'Select an Option:')}{' ' * 28}{_c(G, '│')}")
    print(f"  {_c(G, '├' + '─' * 46 + '┤')}")
    print(f"  {_c(G, '│')}  {_c(C, '[1]')} Subdomain Enumeration (Wordlist)    {_c(G, '│')}")
    print(f"  {_c(G, '│')}  {_c(C, '[2]')} DNS Record Enumeration               {_c(G, '│')}")
    print(f"  {_c(G, '│')}  {_c(C, '[3]')} Reverse DNS Lookup                   {_c(G, '│')}")
    print(f"  {_c(G, '│')}  {_c(C, '[4]')} Wildcard DNS Detection               {_c(G, '│')}")
    print(f"  {_c(G, '│')}  {_c(C, '[5]')} Custom Wordlist Scan (File)          {_c(G, '│')}")
    print(f"  {_c(G, '│')}  {_c(R, '[6]')} Exit                                 {_c(G, '│')}")
    print(f"  {_c(G, '└' + '─' * 46 + '┘')}")
    print()


def _section_header(title):
    """Print a coloured section header."""
    print()
    _sep('═')
    print(f"  {_c(G, BOLD + title)}")
    _sep('═')
    print()


def _input(prompt):
    """Coloured input prompt."""
    return input(f"  {_c(P, BOLD + '[>]')} {_c(W, prompt)}: ").strip()


# ============================================================
# Main Application
# ============================================================

def main():
    """Main application entry point and event loop."""
    display_banner()

    while True:
        display_menu()

        try:
            raw = input(f"  Enter your choice {_c(P, BOLD + '[1/2/3/4/5/6]')}"
                        f" {_c(G, '(1)')}: ")
            choice = raw.strip() or '1'

            if choice == '1':
                _section_header("SUBDOMAIN ENUMERATION  —  Built-in Wordlist")
                domain = _input("Enter target domain (e.g., example.com)")
                if not domain:
                    print(f"  {_c(R, '[!]')} Domain cannot be empty.")
                    continue
                threads_in = _input("Number of threads (default 20)")
                num_threads = int(threads_in) if threads_in.isdigit() else 20

                finder = SubdomainFinder(domain)
                gen = WordlistGenerator()
                wordlist = gen.generate()
                finder.scan_wordlist(wordlist, num_threads=num_threads)

                if len(finder.found) > 0:
                    save = _input("Save results to file? (y/n)").lower()
                    if save == 'y':
                        fname = finder.save_results()
                        print(f"\n  {_c(G, '[+]')} Results saved to: {_c(C, fname)}")

            elif choice == '2':
                _section_header("DNS RECORD ENUMERATION")
                domain = _input("Enter target domain")
                if not domain:
                    print(f"  {_c(R, '[!]')} Domain cannot be empty.")
                    continue
                enumerator = DNSEnumerator(domain)
                enumerator.enumerate_all()

            elif choice == '3':
                _section_header("REVERSE DNS LOOKUP")
                ip_input = _input("Enter IP address(es) (comma-separated)")
                if not ip_input:
                    print(f"  {_c(R, '[!]')} IP address cannot be empty.")
                    continue
                ip_list = [ip.strip() for ip in ip_input.split(',') if ip.strip()]
                rdns = ReverseDNSLookup()
                rdns.bulk_lookup(ip_list)

            elif choice == '4':
                _section_header("WILDCARD DNS DETECTION")
                domain = _input("Enter target domain")
                if not domain:
                    print(f"  {_c(R, '[!]')} Domain cannot be empty.")
                    continue
                finder = SubdomainFinder(domain)
                print(f"\n  {_c(C, '[*]')} Testing wildcard DNS for: {_c(G, BOLD + domain)}")
                if finder.detect_wildcard():
                    print(f"  {_c(R, '[!]')} {_c(R, BOLD + 'WARNING: Wildcard DNS detected!')}")
                    print(f"  {_c(R, '[!]')} Wildcard IPs : {_c(Y, ', '.join(finder.wildcard_ips))}")
                    print(f"  {_c(R, '[*]')} Any subdomain will resolve — results require filtering.")
                else:
                    print(f"  {_c(G, '[+]')} No wildcard DNS detected for: {_c(G, BOLD + domain)}")
                    print(f"  {_c(G, '[+]')} Domain is safe to enumerate without false positives.")

            elif choice == '5':
                _section_header("CUSTOM WORDLIST SCAN  —  File Input")
                domain = _input("Enter target domain")
                if not domain:
                    print(f"  {_c(R, '[!]')} Domain cannot be empty.")
                    continue
                wordlist_path = _input("Enter wordlist file path")
                if not os.path.exists(wordlist_path):
                    print(f"  {_c(R, '[!]')} File not found: {_c(Y, wordlist_path)}")
                    continue
                with open(wordlist_path, 'r') as wf:
                    custom_words = [line.strip() for line in wf if line.strip()]
                print(f"  {_c(C, '[*]')} Loaded {_c(G, str(len(custom_words)))} "
                      f"words from: {_c(C, wordlist_path)}")
                threads_in = _input("Number of threads (default 20)")
                num_threads = int(threads_in) if threads_in.isdigit() else 20

                finder = SubdomainFinder(domain)
                finder.scan_wordlist(custom_words, num_threads=num_threads)

                if len(finder.found) > 0:
                    save = _input("Save results to file? (y/n)").lower()
                    if save == 'y':
                        fname = finder.save_results()
                        print(f"\n  {_c(G, '[+]')} Results saved to: {_c(C, fname)}")

            elif choice == '6':
                print()
                print(f"  {_c(R, 'Exiting ...')}")
                print()
                sys.exit(0)

            else:
                print(f"\n  {_c(R, '[!]')} Invalid option. Please select 1-6.")

            print()
            input(f"  {_c(DIM, '[*] Press Enter to continue...')}")
            display_banner()

        except KeyboardInterrupt:
            print(f"\n\n  {_c(R, 'Exiting ...')}\n")
            sys.exit(0)
        except Exception as e:
            print(f"\n  {_c(R, '[!]')} Error: {_c(Y, str(e))}")
            input(f"\n  {_c(DIM, '[*] Press Enter to continue...')}")


if __name__ == "__main__":
    main()
