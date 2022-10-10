#!/usr/bin/env python3
#POST request user enumeration tool
#JoaoVitorBF

from multiprocessing import Process, Queue
from statistics import mean
from urllib3 import exceptions as urlexcept
import argparse
import requests
import math

def process_enum(queue, found_queue, wordlist, url, payload, failstr, verbose, proc_id, stop):
    try:
        # Payload to dictionary
        payload_dict = {}
        for load in payload:
            split_load = load.split(":")
            if split_load[1] != '{USER}':
                payload_dict[split_load[0]] = split_load[1]
            else:
                payload_dict[split_load[0]] = '{USER}'
        
        # Enumeration
        total = len(wordlist)
        for counter, user in enumerate(wordlist):
            user_payload = dict(payload_dict)
            for key, value in user_payload.items():
                if value == '{USER}':
                    user_payload[key] = user
            r = requests.post(url, data=user_payload)
            if failstr not in r.text:
                queue.put((proc_id, "FOUND", user))
                found_queue.put((proc_id, "FOUND", user))
                if stop: break
            elif verbose:
                queue.put((proc_id, "TRIED", user))
            queue.put(("PERCENT", proc_id, (counter/total)*100))
    except (urlexcept.NewConnectionError, requests.exceptions.ConnectionError):
        print("[ATTENTION] Connection error on process {}! Try lowering the amount of threads with the -c parameter.".format(proc_id))


if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(description="POST request user enumeration tool")
    parser.add_argument("wordlist", help="username wordlist")
    parser.add_argument("url", help="the URL to send requests to")
    parser.add_argument("payload", nargs='+', help="the POST request payload to send")
    parser.add_argument("failstr", help="failure string to search in the response body")
    parser.add_argument("-c", metavar="cnt", type=int, default=10, help="process (thread) count, default 10, too many processes may cause connection problems")
    parser.add_argument("-v", action="store_true", help="verbose mode")
    parser.add_argument("-s", action="store_true", help="stop on first user found")
    args = parser.parse_args()

    # Arguments to simple variables
    wordlist = args.wordlist
    url = args.url
    payload = args.payload
    verbose = args.v
    thread_count = args.c
    failstr = args.failstr
    stop = args.s

    print(""" __              __   __   __ ___                      
|_   _       _  |__) /  \ (_   |     _ |_  _   _ |_  _ 
|__ | ) |_| ||| |    \__/ __)  |    _) |_ (_| |  |_ _)                                                      
""")
    print("URL: "+url)
    print("Payload: "+str(payload))
    print("Fail string: "+failstr)
    print("Wordlist: "+wordlist)
    if verbose: print("Verbose mode")
    if stop: print("Will stop on first user found")

    print("Initializing processes...")
    # Distribute wordlist to processes
    wlfile = open(wordlist, "r", encoding="ISO-8859-1")
    tothread = 0
    wllist = [[] for i in range(thread_count)]
    for user in wlfile:
        wllist[tothread-1].append(user.strip())
        if (tothread < thread_count-1):
            tothread+=1
        else:
            tothread = 0
    
    # Start processes
    tries_q = Queue()
    found_q = Queue()
    processes = []
    percentage = []
    last_percentage = 0
    for i in range(thread_count):
        p = Process(target=process_enum, args=(tries_q, found_q, wllist[i], url, payload, failstr, verbose, i, stop,))
        processes.append(p)
        percentage.append(0)
        p.start()
    
    print("Processes started successfully! Enumerating.")
    # Main process loop
    initial_count = len(processes)
    while True:
        # Read the process output queue
        try:
            oldest = tries_q.get(False)
            if oldest[0] == 'PERCENT':
                percentage[oldest[1]] = oldest[2]
            elif oldest[1] == 'FOUND':
                print("[{}] FOUND: {}".format(oldest[0], oldest[2]))
            elif verbose:
                print("[{}] Tried: {}".format(oldest[0], oldest[2]))
        except: pass

        # Calculate completion percentage and print if /10
        total_percentage = math.ceil(mean(percentage))
        if total_percentage % 10 == 0 and total_percentage != last_percentage:
            print("{}% complete".format(total_percentage))
            last_percentage = total_percentage

        # Pop dead processes
        for k, p in enumerate(processes):
            if p.is_alive() == False:
                processes.pop(k)
        
        # Terminate all processes if -s flag is present
        if len(processes) < initial_count and stop:
            for p in processes:
                p.terminate()

        # Print results and terminate self if finished
        if len(processes) == 0:
            print("EnumPOST finished, and these usernames were found:")
            while True:
                try:
                    entry = found_q.get(False)
                    print("[{}] FOUND: {}".format(entry[0], entry[2]))
                except:
                    break
            quit()