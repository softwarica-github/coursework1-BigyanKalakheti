def difference(string1, string2):
      # Split both strings into list items
  string1 = string1.split()
  string2 = string2.split()

  A = set(string1) # Store all string1 list items in set A
  B = set(string2) # Store all string2 list items in set B
 
  str_diff = A.symmetric_difference(B)
  isEmpty = (len(str_diff) == 0)
 
  if isEmpty:
    print("Unknown error")
  else:
    print("\n")
    # print(f"type: {type(str_diff)}")
    # print(str_diff)
    # for value in str_diff:
    #     if "~~" in value:
    #         print(value)
    filtered_values = []

    for value in str_diff:
        start_index = value.find(">")
        end_index = value.find("<", start_index)
        
        if "~~" in value and start_index != -1 and end_index != -1:
            substring_between_gt_lt = value[start_index + 1:end_index]
            filtered_values.append(substring_between_gt_lt)

    # print(filtered_values)
    return (filtered_values)
#   print('The programs runs successfully.')

# Driver code to call a function
# usr_str1 = 'Educative is good'
# usr_str2 = 'Educative is bad'
# output = difference(usr_str1, usr_str2)
