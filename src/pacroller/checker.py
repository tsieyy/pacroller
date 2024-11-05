import logging
from typing import List, Tuple, Dict, Self
from pathlib import Path
from time import ctime, time
from re import compile, Pattern, match
from pacroller.utils import pacman_time_to_timestamp
from pacroller.known_output import KNOWN_HOOK_OUTPUT, KNOWN_PACKAGE_OUTPUT
from pacroller.config import IGNORED_PACNEW


logger = logging.getLogger()

REGEX: Dict[str, Pattern[str]] = {
    's_process_pkg_changes': r':: Processing package changes\.\.\.',
    's_post-transaction': r':: Running post-transaction hooks\.\.\.$',
    's_optdepend': r'(?i)(?:new )?optional dependencies for (.+)$',
    's_optdepend_list': r'    ([^:^ ]+).*',
    'l_running_hook': r'running \'(.+)\'\.\.\.',
    'l_transaction_start': r'transaction started',
    'l_transaction_complete': r'transaction completed',
    'l_upgrade': r'upgraded (.+) \((.+) -> (.+)\)',
    'l_install': r'installed (.+) \((.+)\)',
    'l_downgrade': r'downgraded (.+) \((.+) -> (.+)\)',
    'l_reinstall': r'reinstalled (.+) \((.+)\)',
    'l_remove': r'removed (.+) \((.+)\)',
    'l_pacnew': r'warning: (.+) installed as (.+\.pacnew)',
}
for k, v in REGEX.items():
    REGEX[k] = compile(v)


class CheckReport:
    def __init__(self, info: List[str] = None, warn: List[str] = None,
                 crit: List[str] = None, changes: List[Tuple[str, ...]] = None,
                 date: int = int(time())) -> None:
        self._info = info or list()
        self._warn = warn or list()
        self._crit = crit or list()
        self._changes = changes or list()
        self._date = date

    @property
    def failed(self, extra_safe: bool = False) -> bool:
        if extra_safe:
            if self._info or self._warn or self._crit:
                return True
        else:
            if self._warn or self._crit:
                return True
        return False

    def to_dict(self) -> dict:
        return {'info': self._info, 'warn': self._warn, 'crit': self._crit, 'changes': self._changes, 'date': self._date}

    def summary(self, verbose=True, show_package=False, indent=2) -> str:
        ret = [f"Pacroller Report at {ctime(self._date)}",]
        if self._crit:
            ret.append("Collected Errors:")
            ret.extend([" " * indent + i for i in self._crit])
        if self._warn:
            ret.append("Collected Warnings:")
            ret.extend([" " * indent + i for i in self._warn])
        if verbose and self._info:
            ret.append("Collected Info:")
            ret.extend([" " * indent + i for i in self._info])
        if show_package:
            pkg_ret = list()
            installed = list()
            upgraded = list()
            removed = list()
            for c in self._changes:
                name, old, new = c
                if old and new:
                    upgraded.append(c)
                elif old is None:
                    installed.append(c)
                elif new is None:
                    removed.append(c)
                else:
                    raise RuntimeError(f"{c=}")
            if verbose:
                for c in upgraded:
                    name, old, new = c
                    pkg_ret.append(f'upgrade {name} from {old} to {new}')
                for c in installed:
                    name, _, new = c
                    pkg_ret.append(f'install {name} {new}')
                for c in removed:
                    name, old, _ = c
                    pkg_ret.append(f'remove {name} {old}')
            else:
                up, ins, rem = [[c[0] for c in x] for x in (upgraded, installed, removed)]
                if up:
                    pkg_ret.append(f'upgrade: {" ".join(up)}')
                if ins:
                    pkg_ret.append(f'install: {" ".join(ins)}')
                if rem:
                    pkg_ret.append(f'remove: {" ".join(rem)}')
            if pkg_ret:
                ret.append("Package changes:")
                ret.extend([" " * indent + i for i in pkg_ret])
        if len(ret) == 1:
            ret.append('nothing to show')
        return "\n".join(ret)

    def info(self, text: str) -> None:
        logger.debug(f'report info {text}')
        self._info.append(text)

    def warn(self, text: str) -> None:
        logger.debug(f'report warn {text}')
        self._warn.append(text)

    def crit(self, text: str) -> None:
        logger.debug(f'report crit {text}')
        self._crit.append(text)

    def change(self, name: str, old: str, new: str) -> None:
        logger.debug(f'report change {name=} {old=} {new=}')
        self._changes.append((name, old, new))

    def stdout_parser(self, stdout: List[str]) -> None:
        ln = 0
        in_package_change = False
        while ln < len(stdout):
            line = stdout[ln]
            if REGEX['s_process_pkg_changes'].match(line):
                in_package_change = True
                ln += 1
                continue
            elif REGEX['s_post-transaction'].match(line):
                in_package_change = False
                # we don't care anything below this
                logger.debug(f'break {line=}')
                break
            if in_package_change:
                if _m := REGEX['s_optdepend'].match(line):
                    logger.debug(f'optdepend start {line=}')
                    pkg = _m.groups()[0]
                    optdeps = list()
                    while True:
                        ln += 1
                        line = stdout[ln]
                        if _m := REGEX['s_optdepend_list'].match(line):
                            logger.debug(f'optdepend found {line=}')
                            optdeps.append(_m.groups()[0])
                        else:
                            logger.debug(f'optdepend end {line=}')
                            ln -= 1
                            break
                    self.info(f'new optional dependencies for {pkg}: {", ".join(optdeps)}')
                else:
                    logger.debug(f'stdout {line=} is unknown')
            else:
                logger.debug(f'skip {line=}')
            ln += 1

    def log_parser(self, log: List[str]) -> None:
        # preprocess
        if log[-1] == '':
            log = log[:-1]
        nlog = list()
        for line in log:
            try:
                _split_log_line(line)
                nlog.append(line)
            except Exception:
                logger.debug(f"preprocess logs: should not be on a new line, {line=}")
                assert nlog
                nlog[-1] = f"{nlog[-1]} {line}"
        log = nlog
        ln = 0
        in_transaction = 0
        while ln < len(log):
            line = log[ln]
            (_, source, msg) = _split_log_line(line)
            if source == 'PACMAN':
                pass # nothing concerning here
            elif source == 'ALPM':
                if _m := REGEX['l_upgrade'].match(msg):
                    self.change(*(_m.groups()))
                elif _m := REGEX['l_install'].match(msg):
                    name, new = _m.groups()
                    self.change(name, None, new)
                elif _m := REGEX['l_remove'].match(msg):
                    name, old = _m.groups()
                    self.change(name, old, None)
                elif _m := REGEX['l_downgrade'].match(msg):
                    name, old, new = _m.groups()
                    self.warn(f"downgrade {name} from {old} to {new}")
                elif _m := REGEX['l_reinstall'].match(msg):
                    name, new = _m.groups()
                    self.warn(f"reinstall {name} {new}")
                elif REGEX['l_transaction_start'].match(msg):
                    logger.debug('transaction_start')
                    if in_transaction == 0:
                        in_transaction = 1
                    else:
                        self.crit(f'{ln=} duplicate transaction_start')
                elif REGEX['l_transaction_complete'].match(msg):
                    logger.debug('transaction_complete')
                    if in_transaction == 1:
                        in_transaction = 2
                    else:
                        self.crit(f'{ln=} transaction_complete while {in_transaction=}')
                elif _m := REGEX['l_pacnew'].match(msg):
                    orig, _ = _m.groups()
                    if orig in IGNORED_PACNEW:
                        logger.debug(f'pacnew ignored for {orig}')
                    else:
                        self.warn(f'please merge pacnew for {orig}')
                elif _m := REGEX['l_running_hook'].match(msg):
                    hook_name = _m.groups()[0]
                    logger.debug(f'hook start {hook_name=}')
                    while True:
                        ln += 1
                        if ln >= len(log):
                            logger.debug(f'hook end {hook_name=} {msg=}')
                            ln -= 1
                            break
                        line = log[ln]
                        (_, source, msg) = _split_log_line(line)
                        if source == 'ALPM-SCRIPTLET':
                            for r in (*(KNOWN_HOOK_OUTPUT.get('', [])), *(KNOWN_HOOK_OUTPUT.get(hook_name, []))):
                                if match(r, msg):
                                    logger.debug(f'hook output match {hook_name=} {msg=} {r=}')
                                    break
                            else:
                                self.warn(f'hook {hook_name} says {msg}')
                        else:
                            logger.debug(f'hook end {hook_name=} {msg=}')
                            ln -= 1
                            break
                else:
                    self.crit(f'[NOM-ALPM] {msg}')
            elif source == 'ALPM-SCRIPTLET':
                (_sourcem1, _, _pmsg) = _split_log_line(log[ln-1])
                for action in {'upgrade', 'install', 'remove', 'downgrade', 'reinstall'}:
                    if _m := REGEX[f"l_{action}"].match(_pmsg):
                        pkg, *_ = _m.groups()
                        break
                else:
                    self.crit(f'[NOM-SCRIPTLET] {msg} {_pmsg}')
                    ln += 1
                    action = 'unknown'
                    continue
                logger.debug(f'.install start {pkg=} {action=}')
                while True:
                    line = log[ln]
                    (_, source, msg) = _split_log_line(line)
                    if source == 'ALPM-SCRIPTLET':
                        for r in (*(KNOWN_PACKAGE_OUTPUT.get('', [])), *(KNOWN_PACKAGE_OUTPUT.get(pkg, []))):
                            if isinstance(r, dict):
                                if action in r.get('action'):
                                    if match(r.get('regex'), msg):
                                        logger.debug(f'.install output match {pkg=} {action=} {msg=} {r=}')
                                        break
                            else:
                                if match(r, msg):
                                    logger.debug(f'.install output match {pkg=} {msg=} {r=}')
                                    break
                        else:
                            self.warn(f'package {pkg} says {msg}')
                    else:
                        logger.debug(f'.install end {pkg=} {msg=}')
                        ln -= 1
                        break
                    ln += 1
            else:
                self.crit(f'{line=} has unknown source')
            ln += 1

    @classmethod
    def log_checker(cls,  stdout: List[str], log: List[str], debug=False) -> Self:
        if debug:
            Path('/tmp/pacroller-stdout.log').write_text('\n'.join(stdout))
            Path('/tmp/pacroller-pacman.log').write_text('\n'.join(log))
        report = cls()
        report.stdout_parser(stdout)
        report.log_parser(log)
        return report

def _split_log_line(line: str) -> Tuple[int, str, str]:
    time, source, msg = line.split(' ', maxsplit=2)
    time: int = pacman_time_to_timestamp(str(time).strip('[]'))
    source = source.strip('[]')
    return time, source, msg

def sync_err_is_net(output: str) -> bool:
    ''' check if a sync failure is caused by network '''
    output = output.strip().split('\n')
    if 'error: failed to synchronize all databases (download library error)' in output \
        or 'error: failed to synchronize all databases (unexpected error)' in output:
        return True
    else:
        return False

def upgrade_err_is_net(output: str) -> bool:
    ''' check if an upgrade failure is caused by network '''
    output = output.strip().split('\n')
    if len(output) >= 2 and 'warning: failed to retrieve some files' in output and \
       'error: failed to commit transaction (failed to retrieve some files)' in output:
        return True
    else:
        return False

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(module)s - %(funcName)s - %(levelname)s - %(message)s')
    stdout = Path('/tmp/pacroller-stdout.log').read_text().split('\n')
    # log = Path('/tmp/pacroller-pacman.log').read_text().split('\n')
    report = CheckReport()
    report.stdout_parser(stdout)
    # report.log_parser(log)
    print(report.to_dict())
    print(report.summary(show_package=True, verbose=True))
