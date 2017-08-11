# SimplePEViewer

## Introduction

A Simple PE Viewer.

Although someone has developed a [better one](https://github.com/erocarrera/pefile), I'd like to try it myself.

## Install

I haven't package it, so just download PEFile.py and import it like a module.

## Usage

First import the module.

```python
from PEFile import PEFile
```

And then open a file.

```python
file = PEFile(path_to_your_file)
```

If the file doesn't exist, it will raise an error.

Next, read the header.

```python
file.readheader()
```

The PE Header is stored in dict, like the struct in C.

```python
file.IMAGE_DOS_HEADER['e_lfanew']
file.IMAGE_NT_HEADERS['Signature']
```

Also, some headers array are in list, like:

```python
file.IMAGE_SECTION_HEADER[0]['Name']
```

Note: All stored value is bytes, if you expect a human-readable format, try this.

```python
file.IMAGE_NT_HEADERS['Signature'].hex()
```

## Recent Change

I have decided to **stop** the development.

It is much more complicated than I expected before, so I just develop a few basic functions to understand the PE format.