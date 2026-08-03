#!/usr/bin/env python3
"""Test script for LLM attack insights function"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from llm_analysis import get_llm_attack_insights

# Sample nmap output for testing
test_nmap_output = """
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https

Nmap scan report for 192.168.1.100
Host is up (0.012s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6
3306/tcp open  mysql   MySQL 5.7.25
"""

if __name__ == "__main__":
    print("Testing LLM attack insights function...")
    print("=" * 50)
    
    result = get_llm_attack_insights(test_nmap_output)
    
    if result:
        print("LLM Analysis Result:")
        print("-" * 30)
        print(result)
        print("-" * 30)
        print(f"Result length: {len(result)} characters")
    else:
        print("❌ LLM analysis failed or returned empty result")
        print("Check that enable_llm_analysis is true and llm_model is explicitly configured")
