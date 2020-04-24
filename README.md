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
$ git clone https://github.com/joshzelonis/EnterpriseAPT29Eval.git
```
From the root of this project, install the PIP requirements.
```
$ pip3 install -r requirements.txt
```
Then use my incredibly (in)elegant curl script to pull down the vendor scores.
```
$ chmod +x pull_scores.sh
$ ./pull_scores.sh
```
Finally, run the thing!
```
$ python3 EnterpriseAPT29Eval.py 
```
## FAQ
Q: Why do you find more 'None' values than are reported when I grep for it?

A: There are instances where the scoring will show an MSSP detection and no other detection. From what I can tell, this impacts many of the score sheets (i.e. - SentinelOne SubStep 13.B.1) and leads to some oddities in the data:
 - The number of 'None' detections I report in the xlsx may be higher than what you get when you grep these files.
 - Kaspersky had 124.56% detection rate by their MSSP versus the telemetry they were collecting with the product.
 - Also anticipate this behavior if all the detections came in due to configuration changes as these are likely ignored (see next).


Q: Why don't you count config changes?

A: I'm trying to identify what a majority of companies would be looking at when trying to do a detection. I do actually count detections that include both versions of config changes and throw this in a property called 'dfir' because I expect this level of tuning would likely only be in use during an incident response or 


## Thanks
I want to thank MITRE for the ATT&CK Framework and for performing these open and transparent evaluations.

I also want to thank the 21 vendors who participated in this evaluation for providing transparency into the efficacy of their products. 

You are all making the world more secure.
