# PDF Analysis links

* some good tips by [angelalbertini](https://twitter.com/angealbertini/status/1061008041640972288):
  * Generic advice to make PDF manipulations by hand (fill forms, modify contents...):
    1. run `qpdf -qdf` to normalize the PDF [optionally with --stream-data=uncompress].
    2. do your changes.
    3. clean up the PDF with `mutool clean`.
    4. remember that some fields like author can be stored as Unicode: so 'ange' = 00 61 00 6E 00 67 00 65
    5. inline kerning is often used (by LaTeX, etc...) in the pages contents: it's an array of a short string (w/ parenthesis), a number, a short string...
    6. so 'ange' can be stored like: [(an) 3.0 (ge)]
  * [PDF Cheat Sheets](https://github.com/gendx/pdf-cheat-sheets): Cheat sheets for the Portable Document Format


## Links 

* [PDFObject](https://pdfobject.com/): An open-source standards-friendly JavaScript utility for embedding PDF files into HTML documents.
* [PDF](https://www.forensicswiki.org/wiki/PDF) on Forensics Wiki
* [PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/) by Didier Stevens
* [How to Embed JavaScript into PDF](http://mariomalwareanalysis.blogspot.com/2012/02/how-to-embed-javascript-into-pdf.html)
* [PJScan](https://seclist.wordpress.com/2011/12/10/pjscan-a-command-line-utility-that-uses-a-learning-algorithm-to-detect-pdf-files-with-javascript-related-malware-i-e-malicious-pdf-files/)a command-line utility that uses a learning algorithm to detect PDF files with JavaScript-related malware - [sourceforge](https://sourceforge.net/projects/pjscan/) repo.
* [RUPS](https://github.com/itext/rups) is an abbreviation for Reading and Updating PDF Syntax. RUPS is a tool built on top of iText® that allows you to look inside a PDF document and browse the different PDF objects and content streams.
* [CLI pdf viewer for linux](https://stackoverflow.com/questions/3570591/cli-pdf-viewer-for-linux) - stackoverflow
* [PeePDF](https://github.com/jesparza/peepdf): Powerful Python tool to analyze PDF documents
* [pdfstreamdumper](https://github.com/dzzie/pdfstreamdumper): research tool for the analysis of malicious pdf documents. make sure to run the installer first to get all of the 3rd party dlls installed correctly. 
* [pdfextract](https://github.com/CrossRef/pdfextract):  A tool and library that can extract various areas of text from a PDF, especially a scholarly article PDF. 
* [4Discovery Tools](http://www.4discovery.com/our-tools/)
* PDF Automation/Manipulation: 
  * [Create and Modify PDF Files in Python](https://realpython.com/creating-modifying-pdf/#encrypting-and-decrypting-pdf-files-with-pypdf)
  * [Distributed Steganography in PDF Files—Secrets Hidden in Modified Pages](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7517136/)  
