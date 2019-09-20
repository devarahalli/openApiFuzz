"""
This module helps to analyze the result of peach Fuzz test and generates the output file which will be used 
for filing the GIT issues.
Author : prakash.d@nokia.com
Date : 18-Sep-2019
"""

class AnalyzeApiFailures :
  def statusCodeCheck (data, code ) :
      if data['status_code'] >= code and data ['status_code'] <= (code + 99):
        return True
      return False 

  def descCodeCheck (data,cmpStr ):
      if data['description']['description_code'] in cmpStr : 
        return True
      return False 
 
  def responseTimeValidation(data,timeout):
    if data['rtt'] >= timeout :
      return True
    return False 
      
  def checkCodeLeak (self ) :
    pass


