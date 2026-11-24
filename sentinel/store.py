import sqlite3, json
from pathlib import Path
import os
from .evidence import sanitize

class Store:
    def __init__(self, path=None):
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home()/'.local'/'share')/'Sentinel'
        if path is None:
            base.mkdir(parents=True, exist_ok=True)
            path = base/'sentinel.sqlite3'
        self.conn = sqlite3.connect(path)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.executescript('''CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, project INTEGER NOT NULL REFERENCES projects(id), target TEXT NOT NULL, started TEXT NOT NULL, result TEXT NOT NULL);''')
        self.conn.commit()
    def project(self, name):
        name = name.strip()
        if not name: raise ValueError('Enter a project name.')
        with self.conn:
            self.conn.execute('INSERT OR IGNORE INTO projects(name) VALUES (?)',(name,))
        return self.conn.execute('SELECT id FROM projects WHERE name=?',(name,)).fetchone()[0]
    def projects(self):
        return [r[0] for r in self.conn.execute('SELECT name FROM projects ORDER BY name')]
    def save(self, project, result):
        result = sanitize(result)
        with self.conn:
            cur = self.conn.execute('INSERT INTO scans(project,target,started,result) VALUES (?,?,?,?)',(project,result['target'],result['started'],json.dumps(result)))
        return cur.lastrowid
    def history(self, project):
        return [(r[0],sanitize(json.loads(r[1]))) for r in self.conn.execute('SELECT id,result FROM scans WHERE project=? ORDER BY id DESC',(project,))]
    def close(self): self.conn.close()
