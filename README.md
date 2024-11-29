# Phishing Incident Report

[Link to Email Header](https://github.com/LGOG/Masterschool/blob/Phishing-Analysis/mail.eml#L1)

## Email Header Details and Content Description

1. **From:**
    - **Spoofed Email**: The sender appears to be Mikel from (g[.]corp[.]sender@gmail[.]com), spoofing Google.
    - **Original Sender**: After investigating the email header, I identified the actual sending domain as (6B7EC235-5B17-4CA8-B2B8-39290DEB43A3@test[.]lindsaar[.]net).

       **To:** Leeor@masterschool[.]com

2. **Subject**: Black Friday early access
3. **Received From**: 194.25.134.80 (Reverse DNS: mailout01[.]t-online[.]de)

The sending server’s IP address, 194.25.134.80, is located in Australia, confirmed by lookup. This did not originate from Google’s infrastructure.

4. **Content**: The email body includes a link to a supposed Google offer, but further investigation revealed the link redirects to a suspicious Ukrainian site.

## Artifacts Collected

1. **Suspicious URL**:
    - The visible link appears to be a Google domain (hxxps[://]store[.]google[.]com/collection/offers?hl=en-US), but on closer inspection, it redirects to a suspicious domain (hxxp[://]006[.]zzz[.]com[.]ua/).
    - **Actions**: I used tools like VirusTotal and URL2PNG to inspect the destination domain and found it likely to be malicious, hosted on a Ukrainian web server.

2. **Attachment**:
    - A .docx file titled "Black Friday early access.docx" was attached. Upon examination, the file was found to be **0 bytes**, indicating a possible attempt to evade detection by security filters.
    - **Hash Analysis**: I calculated the file’s hashes using MD5, SHA-1, and SHA-256. The results indicated it was an empty file but still suspicious due to its association with the phishing email.

    - **MD5**: `d41d8cd98f00b204e9800998ecf8427e`
    - **SHA-1**: `da39a3ee5e6b4b0d3255bfef95601890afd80709`
    - **SHA-256**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

## Users Affected and Notification Actions

1. **Affected User**: The recipient, Leeor G (Leeor@masterschool[.]com), was notified immediately about the phishing attempt. I advised them not to open the attachment or click on the links.

## Analysis Process and Results

1. **Tools Used**:
    - **Phishtool**: Used for analyzing the email’s journey across various servers and identifying the originating ISP (TPG Internet in Australia).
    - **URL2PNG**: I used this to capture the look of the suspicious website without directly visiting it.
    - **VirusTotal**: I uploaded the link and attachment hashes to check for any prior reports or known malicious activity.
    - **dig** and **whois**: Performed DNS lookups to verify the IP address and examine the DMARC, SPF, and DKIM status for email authentication.

2. **Key Results**:
    - **Email Origin**: The email did not originate from Google’s infrastructure. Instead, it came from an Australian ISP (TPG Internet). (g[.]corp[.]sender@gmail[.]com) → (test[.]lindsaar[.]net).
    - **Redirected URL**: The suspicious URL (hxxp[://]006[.]zzz[.]com[.]ua/) was flagged as dangerous. It likely leads to a phishing site.
    - **Attachment Analysis**: Despite being an empty .docx file, the attachment is suspicious and could be part of a broader phishing tactic, like bypassing filters or encouraging the user to engage with the malicious content.

3. **Authentication Failures**:
    - **SPF (Sender Policy Framework)**: The result is **SOFTFAIL**, meaning the originating IP (**194.25.134.80**) is not authorized by the SPF record of gmail.com. This indicates the email might be spoofed but not explicitly rejected.
    - **DKIM (DomainKeys Identified Mail)**: **None**, meaning the email was not signed with DKIM, which helps validate email authenticity.
    - **DMARC (Domain-based Message Authentication)**: The result is **FAIL**, confirming the email doesn’t align with Gmail’s DMARC policy, strongly suggesting it’s a spoofed email.

<img width="568" alt="Email Header Screenshot" src="https://github.com/user-attachments/assets/ba4df13d-d347-44a5-87ec-d9baa484436c">


## Visual Evidence

1. **Reverse DNS Lookup**:
    - I used dig -x to perform a reverse lookup on the IP address from the email header. The analysis confirmed that the email did not originate from Google but instead passed through multiple unrelated servers:
        1. **Originating Server (Australia)**: The email was initially sent from an Australian ISP (60-241-138-146.static.tpgi.com.au), which is part of TPG Internet.
        2. **Intermediate Server (Germany)**: It was then routed through a German server (mailout01.t-online.de) belonging to T-Online.
    This clearly demonstrates that the email was not sent from Google’s infrastructure, despite the spoofed address claiming to be from a Gmail domain.



   <img width="588" alt="Reverse DNS Lookup Screenshot" src="https://github.com/user-attachments/assets/7912d137-6340-4a3b-a69d-d4a1c3d5e2c9">


3. **Email Hop Analysis**:
    - Using Phishtool, I analyzed the email’s journey, tracking its path through the following hops:
    
    - **Hop sequence**:
        1. **Hop 1**:
            Received from 60-241-138-146.static.tpgi.com.au (Australia, TPG Internet).
            This is the originating server used by the attacker.
        2. **Hop 2**:
            Received from mailout01.t-online.de (Germany, T-Online).
            The email was relayed through this server, likely as part of an attempt to obscure its true origin.
        3. **Hop 3**:
            Received by mx.google.com – the mail server used by the recipient.
        4. **Hop 4**:
            Delivered to the recipient’s mailbox at 10.140.178.13.


 <img width="574" alt="Email Hop Analysis Screenshot" src="https://github.com/user-attachments/assets/3bef28cb-a07f-4510-a6af-f8f4e1aef29f">


5. **DMARC Record Check**:
    - Using dig TXT commands, I verified the DMARC record for Gmail, confirming that the email did not pass Gmail’s authentication policies.
    
    - Reveals Gmail's DMARC policy: `v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com`.
    
   <img width="626" alt="DMARC Record Check Screenshot" src="https://github.com/user-attachments/assets/46d11ffc-38e6-49ab-afb0-ab651be413e1">


## Defensive Measures Taken

1. **Flagged the Email**: Marked the email as a phishing attempt in our security system, alerting others to its potential threat.
2. **Blocked the Sender**: I blocked both the spoofed and original sender’s email addresses and the sending IP address (194.25.134.80) to prevent future attempts.
3. **Blacklisted the URLs**: I added the suspicious URLs to our block list to prevent anyone from accessing the malicious site in the future.
4. **Enhanced Monitoring**: Our email filters are now configured to scrutinize similar patterns more thoroughly, focusing on attachments and links.

## Lessons Learned

1. **Employee Training**: This incident emphasizes the need for continuous employee training to spot sophisticated phishing attacks, especially those imitating well-known brands like Google.
2. **Improved Email Filtering**: By enhancing our email filtering protocols, particularly for suspicious URLs and file attachments, we reduce the likelihood of similar threats reaching user inboxes.
3. **DMARC Policy**: Implementing a stricter DMARC policy for our organization would help prevent spoofed emails from being delivered to users.
4. **Email Routing Analysis**: Incorporating email hop analysis into our standard security reviews ensures we can catch anomalies in email paths that indicate possible phishing attempts.
5. **User Education**: Reinforce the importance of verifying the authenticity of email senders and links, especially during high-risk times like Black Friday sales or other promotional periods.

## Contributing

We welcome contributions from the community. If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request. 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or further information, please contact me at [martaa.dominik@gmail.com](mailto:martaa.dominik@gmail.com).

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/marta-dominik-a67803233/)
