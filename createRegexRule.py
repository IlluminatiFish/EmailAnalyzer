def createRule(strings): #Function to create regex rule from a list of strings
    regex_rule = r'(?:' #Prefix of regex rule
    max_size = len(strings) #Total size of list of strings passed
    singular = len(strings) == 1 #If the list has one string inside of it
    iter = 0 #Iterate variable
    for string in strings: #For every string in the list of strings
        if singular: #If the list is singular 
            regex_rule += str(string) #Then add the string to the rule
        else: #If the list has more than one item
            iter += 1 #Add 1 to the iterator
            if iter == max_size: #If the iterator equals the size of starting list
                regex_rule += str(string) #Then add the string to the regex rule
            else: #If the iterator hasn't yet reached the size of the starting list
                regex_rule += str(string) + '|' #Keep adding the string and appending a | next to it so regex can understand the syntax

    regex_rule += ')' #Append a close bracket at the end of the regex rule to finish it
    return regex_rule #Return the generate rule
