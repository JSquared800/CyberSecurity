---
description: Interesting pdf data
---

# picoCTF - Redaction gone wrong

We can't highlight anything in the pdf, but we can use a tool called pdftotext in order to generate a text file for this pdf.

```
┌──(kali㉿kali)-[~/Downloads]
└─$ pdftotext Financial_Report_for_ABC_Labs.pdf 

┌──(kali㉿kali)-[~/Downloads]
└─$ cat Financial_Report_for_ABC_Labs.txt       
Financial Report for ABC Labs, Kigali, Rwanda for the year 2021.
Breakdown - Just painted over in MS word.

Cost Benefit Analysis
Credit Debit
This is not the flag, keep looking
Expenses from the
picoCTF{REDACTED}
Redacted document.
```
