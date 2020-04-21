# EnterpriseAPT29Eval
This project is focused on performing and facilitating analysis of the round 2 results from MITRE's Enterprise ATT&CK Evaluation.

The output of the EnterpriseAPT29Eval.py script is twofold:
1) A cursory analysis of vendor performance based on:
    - How effective their MSSP was at alerting on every single piece of telemetry their products were generating while taking an open book test. (Why no 100%?)
    - An out of the box view of the visibility afforded by the product. In theory, this should represent the best possible detection capability given the infinite monkeys theorem.
    - An out of the box view of the ability of the product to correlate alerts to earlier events. Very few ATT&CK Techniques generate high confidence indictments in isolation, by correlating events we start to have actionable alerts.
2) An XLSX workbook is output to allow you to parse and play with the vendor scores with each vendor receiving their own sheet.

I tried to code this to be as accessible as made sense. Read through the class to identify properties you can directly access and I tried to use my class methods in a manner that would be self documenting. Yes, I just said the code is the documentation, I'm the worst kind of person and I'm comfortable with that.

## Requirements
python3
curl (to download the json data)

## Installation
Start by cloning this repository.
```
git clone https://github.com/joshzelonis/EnterpriseAPT29Eval.git
```
From the root of this project, install the PIP requirements.
```
pip install -r requirements.txt
```
Then use my incredibly (in)elegant curl script to pull down the vendor scores.
```
$ chmod +x pull_scores.sh
$ ./pull_scores.sh
```

## Thanks
I want to thank MITRE for the ATT&CK Framework and for performing these open and transparent evaluations.

I also want to thank the 21 vendors who participated in this evaluation for providing transparency to the efficacy of their products using this evaluation. 

You are all making the world more secure.
