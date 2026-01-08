**SubHunter is a powerful subdomain enumeration tool that leverages Certificate Transparency (CT) logs via crt.sh to discover subdomains for target domains.**


**Features**
```
     Fast JSON API: Uses crt.sh JSON API for blazing-fast results.

     Concurrent Processing: Multi-threaded scanning for bulk domain enumeration (customizable workers).

     Modern CLI: Clean, intuitive interface with real-time logging.

    Flexible Output: Save results to a file or display them in the terminal.

    Silent Mode: Output only results for easy piping into other tools.
````
 **Installation**
```
Since you have fixed the Go module, users can now install it directly:
Bash

go install github.com/aptspider/SubHunter/v2@v2.0.2
````
 Usage
```
Single Domain Scan:
Bash

SubHunter -d example.com

**Bulk Scan with Concurrency: Run against a list of domains with 20 concurrent workers**

SubHunter -l domains.txt -concurrent -c 20 -o results.txt

Silent Mode (For Piping): Pipe subdomains directly into other tools like httpx:
Bash

SubHunter -d example.com -silent | httpx
````

