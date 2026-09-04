# Safe demo walkthrough

Start an entirely offline presentation:

~~~bash
python run_spoofzero.py --demo
~~~

1. Open <http://127.0.0.1:8501>.
2. Expand **Explore with safe built-in evidence**.
3. Choose **Single-email forensic walkthrough** and click **Run offline demo**.
4. Show the forensic score and contribution table. The expected fresh-v2 demo
   score is 75; the experimental AI contribution is 0.
5. Review sender identity, reported authentication, SMTP relays, IOCs, and
   attachment hashes.
6. Point out that external intelligence is labeled unavailable because the demo
   makes no live requests.
7. Create a case and save the result.
8. Run the two related campaign samples, save each to the same case, and inspect
   correlation evidence.
9. Export JSON or HTML and verify its integrity indicator and AI/geolocation
   disclosures.

The demo uses reserved domains, documentation IP ranges, and synthetic content
under data/samples. It never uploads attachments, opens extracted URLs, performs
live reputation calls, or claims a simulated service success.
