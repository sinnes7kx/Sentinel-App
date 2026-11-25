"""Fixed, local SQLite input-handling experiment.

No external database, network, files, user-supplied statements, credentials,
or reusable target interface. Only two disposable synthetic rows exist.
"""
import sqlite3
from contextlib import closing
from threading import Event


def demonstrate_database(cancel=None):
    cancel = cancel if cancel is not None else Event()
    rows = []
    if cancel.is_set():
        return {'status': 'cancelled', 'rows': rows}
    with closing(sqlite3.connect(':memory:')) as db:
        db.execute('CREATE TABLE sample (id INTEGER PRIMARY KEY, label TEXT NOT NULL)')
        db.executemany('INSERT INTO sample VALUES (?, ?)', [(1, 'first'), (2, 'second')])
        # The fixture tests a normal numeric ID and a fixed arithmetic expression.
        # Neither the expression nor the database can be supplied by a caller.
        for label, value, expected_weak, expected_fixed in (
                ('Normal record ID', '1', ('first',), ('first',)),
                ('Unexpected expression', '1+1', ('second',), ())):
            if cancel.is_set():
                break
            weak = tuple(row[0] for row in db.execute(
                'SELECT label FROM sample WHERE id = ' + value))
            fixed = tuple(row[0] for row in db.execute(
                'SELECT label FROM sample WHERE id = ?', (value,)))
            rows.append({'scenario': label, 'weak_count': len(weak), 'protected_count': len(fixed),
                         'weak_second_row': 'second' in weak, 'protected_second_row': 'second' in fixed,
                         'expected': weak == expected_weak and fixed == expected_fixed})
    return {'status': 'cancelled' if cancel.is_set() else
            'completed' if len(rows) == 2 and all(row['expected'] for row in rows) else 'partial',
            'rows': rows}
