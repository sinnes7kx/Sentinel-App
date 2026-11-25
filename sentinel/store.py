import sqlite3, json
from pathlib import Path
import os
from datetime import datetime, timezone
from .evidence import sanitize

REMEDIATION_STATES = ('Open', 'Investigating', 'Remediation applied', 'Retest required')

class Store:
    def __init__(self, path=None):
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home()/'.local'/'share')/'Sentinel'
        if path is None:
            base.mkdir(parents=True, exist_ok=True)
            path = base/'sentinel.sqlite3'
        self.conn = sqlite3.connect(path)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.executescript('''CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, project INTEGER NOT NULL REFERENCES projects(id), target TEXT NOT NULL, started TEXT NOT NULL, result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS remediation_review(scan INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        finding_index INTEGER NOT NULL CHECK(finding_index >= 0), state TEXT NOT NULL, updated TEXT NOT NULL,
        PRIMARY KEY(scan, finding_index));''')
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
    def history(self, project, limit=-1):
        return [(r[0],sanitize(json.loads(r[1]))) for r in self.conn.execute(
            'SELECT id,result FROM scans WHERE project=? ORDER BY id DESC LIMIT ?', (project, limit))]
    def result(self, project, scan_id):
        row = self.conn.execute('SELECT result FROM scans WHERE project=? AND id=?', (project, scan_id)).fetchone()
        return sanitize(json.loads(row[0])) if row else None
    def remediation(self, project, scan_id):
        """Manual review states scoped to a single saved assessment."""
        return {index: {'state': state, 'updated': updated}
                for index, state, updated in self.conn.execute(
                    'SELECT r.finding_index,r.state,r.updated FROM remediation_review r '
                    'JOIN scans s ON s.id=r.scan WHERE s.project=? AND s.id=?',
                    (project, scan_id))}

    def set_remediation(self, project, scan_id, index, state):
        if state not in REMEDIATION_STATES:
            raise ValueError('Unknown remediation status.')
        result = self.result(project, scan_id)
        if result is None or type(index) is not int or not 0 <= index < len(result['findings']):
            raise ValueError('Select a finding in this project assessment.')
        updated = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self.conn:
            self.conn.execute(
                'INSERT INTO remediation_review(scan,finding_index,state,updated) VALUES (?,?,?,?) '
                'ON CONFLICT(scan,finding_index) DO UPDATE SET state=excluded.state,updated=excluded.updated',
                (scan_id, index, state, updated))
        return {'state': state, 'updated': updated}

    def close(self): self.conn.close()
