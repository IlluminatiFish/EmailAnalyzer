# EmailAnalyzer
A short python script that allows you to enter headers from any email service and extracts the relevant data that can be used later on in many ways such as reporting and incident responses.

Icon Key:
| Icon | Description |
| --- | --- |
| `[+]` | Gives informational messages to the user while the analyzer is running |
| `[~]` | Extracted information from the body |
| `[-]` | All errors are marked using this icon |

Informational Key:
| Prefix | Description |
| --- | --- |
| `[MSA]` | Mail submission agent aka the first MTA to submit the email to the internet |
| `[MTA-X]` | Mail transfer agent aka the mail server that transfers the email across the internet to its correct destination, x any number depending on the amount of MTAs that handled the email |
| `[MDA]` | Mail delivery agent aka the mail server that delivers the email to the your inbox/provider |


Libraries used in this script:
```
  - requests
  - socket
  - warnings
  - re
  - ipaddress
  - base64
  - json
  - urllib.parse
  - bs4
  - tld
  ```
