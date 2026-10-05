"""Actual owned public synthetic verifier group; no native host credentials."""
from pathlib import Path
import json,os,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from mutation_primary import NativePrimaryVerifier
from operation_budget import OperationBudget
from authoritative_password import Refused
mode=sys.argv[1]
budget=OperationBudget(int(time.time())+300,maximum_seconds=.4 if mode=='wait' else 1)
budget.attach_owned_process_group()
verifier=NativePrimaryVerifier('alice@example.test',budget)
verifier._command=lambda:(sys.executable,'-I',str(Path(__file__).with_name('mutation_primary_fixture.py')),mode)
began=time.monotonic()
try:accepted=verifier('alice@example.test','public synthetic password');refused=False
except Refused:accepted=False;refused=True
sys.stdout.write(json.dumps({'accepted':accepted,'refused':refused,
 'owned_group':os.getpid()==os.getpgrp(),'cleanup_uncertain':verifier._uncertain,
 'bounded':time.monotonic()-began<.65},separators=(',',':')))
