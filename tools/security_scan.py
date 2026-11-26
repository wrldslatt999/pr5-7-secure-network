"""Required stdlib SAST gate: flag predictable secrets, disabled TLS validation, exec/eval.

This is a deliberately narrow teaching scanner, not a substitute for Bandit/Semgrep.
"""
import ast
import pathlib
import sys

ROOT=pathlib.Path(__file__).resolve().parent.parent
TARGETS=['server','client']
DANGEROUS={'eval','exec'}


def scan(path):
    problems=[]
    tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            if isinstance(node.func,ast.Name) and node.func.id in DANGEROUS:
                problems.append((node.lineno,node.func.id))
            if isinstance(node.func,ast.Attribute) and node.func.attr in {'_create_unverified_context'}:
                problems.append((node.lineno,'disabled SSL verification'))
            for kw in node.keywords:
                if kw.arg in {'verify','check_hostname'} and isinstance(kw.value,ast.Constant) and kw.value.value is False:
                    problems.append((node.lineno,'TLS certificate checks disabled'))
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and ('SECRET' in target.id.upper() or 'PASSWORD' in target.id.upper()) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str) and len(node.value.value)>0:
                    problems.append((node.lineno,'hard-coded secret literal'))
    return problems


def main():
    flagged=[];checked=0
    for dirname in TARGETS:
        for path in (ROOT/dirname).rglob('*.py'):
            checked+=1
            for line,reason in scan(path):flagged.append((str(path.relative_to(ROOT)),line,reason))
    for path,line,reason in flagged:
        print(f'{path}:{line}: security error: {reason}')
    print(f'Checked {checked} Python modules; findings={len(flagged)}')
    return 1 if flagged else 0

if __name__=='__main__':sys.exit(main())
