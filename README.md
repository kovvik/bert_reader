# bert_reader
ACPI BERT/HEST Table reader script

Based on the ACPI and UEFI specifications:
- [https://uefi.org/specs/UEFI/2.11/index.html](https://uefi.org/specs/UEFI/2.11/index.html)
- [https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/18_ACPI_Platform_Error_Interfaces/ACPI_PLatform_Error_Interfaces.html](https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/18_ACPI_Platform_Error_Interfaces/ACPI_PLatform_Error_Interfaces.html)

# Usage
```
usage: bert_reader.py [-h] directory

Decodes ACPI BERT, HEST tables and BERT Data Table

positional arguments:
  directory   acpi tables location

optional arguments:
  -h, --help  show this help message and exit
```
