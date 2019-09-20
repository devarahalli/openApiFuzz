import apifuzz as af 
import argparse
import traceback

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="Type of test : prefix of the log file", type=str, default='openapi2')
parser.add_argument("-f", "--file", help="Provide the valid OpenAPI2.0 file", type=str, required=True)
parser.add_argument("-p", "--pattern", help="Provide the pattern select the api to test ; eg 'wifi|bluetooth|userManagement|provisionManagement' ",
                    type=str, default='.*')
parser.add_argument("-lf", "--logfile", help="Provide the logfile name to store json result", type=str, default='apitest_res.json')
parser.add_argument("-au", "--auth", help="Enable or Disable API authentication, if uname:passwd:loginurl username and pasword", type=str, default='no')

parser.add_argument("-pxy", "--proxy", help="Set http proxy e.g : http://1.1.1.1:8080 ", type=str, default='no')
args = parser.parse_args()


if __name__ == "__main__":

    try:
        if args.proxy is not 'no':
           af.setProxy(args.proxy)
        
        af.createLogFile(args)
        
        af.check_and_delete_files([af.error_file, af.result_file, af.timeout_api_log])
        apiObj = af.loadOpenApiDef(args.file)
        host = apiObj.hostname()
        basepath = apiObj.basepath()

        if args.auth is not 'no' :
            uname, passwd, loginurl = args.auth.split(':')
            url = "https://" + host + basepath + '/' + loginurl
            apiAuth = af.Authenticate(url, uname, passwd)
            _, authToken, refreshToken = apiAuth.getToken()
            t = Thread(target=af.refreshhelperFunc, args=(apiObj,))
            t.daemon = True
            t.start()

        testData = apiObj.testData()

        objPd = af.fuzzApi()
        fuzzPayload = objPd.returnFuzzPayload()
        baseurl = url = "https://" + host + basepath
        af.startFuzz(args, baseurl, testData, fuzzPayload)
        af.logFilter(af.result_file, af.filtered_file)

    except Exception as ERR:
        with open(af.error_file, 'w') as errorlog:
            errorlog.write(traceback.format_exc())
