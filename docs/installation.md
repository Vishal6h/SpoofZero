# Installation

SpoofZero v1.0.0-rc1 requires Python 3.11 or newer. Python 3.12 is the recommended
deployment runtime because it is covered by the container definition and has
broad package support.

~~~bash
git clone <your-local-or-private-repository>
cd EmailForensicsAI
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_spoofzero.py --check
python run_spoofzero.py
~~~

On Windows PowerShell, activate with
<code>.venv\Scripts\Activate.ps1</code>. The same startup command is used on
Windows, macOS, Linux, and WSL. Browse to <http://127.0.0.1:8501>.

The two files <code>ml/phishing_model.joblib</code> and
<code>ml/vectorizer.joblib</code> are the pinned legacy compatibility artifacts.
Do not replace them with research candidates. Candidate binaries and raw
research datasets intentionally remain outside Git.

Use <code>python run_spoofzero.py --demo</code> for an offline presentation. Use
<code>python -m unittest discover -s tests -v</code> for the complete offline
test suite.
