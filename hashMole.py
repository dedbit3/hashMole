import sys
import os
import re
import argparse

def banner():
    ascii = '''
                      _____
                    /"_   _"/
                    |(>)-(<)|
                 ../  " O "  /..
        dEd----""(((:-.,_,.-:)))""--------
        '''
    print(ascii)


def main():

    # print banner
    banner()

    # create parser object
    parser = argparse.ArgumentParser(description='Welcome to hashMole specify directory to start digging!\nExample: hashmole.py /home/user\n')

    # create parser arguments
    parser.add_argument('directory', help='Directory to start recursive dig in')
    parser.add_argument('-r', '--regex', help='Specify custom regex to be included in search')
    parser.add_argument('-o', '--output', help='Specify custom output file for hashes')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase program verbosity (print hashes as they are found!)')

    # parse args into a dictionary
    args = vars(parser.parse_args())


    #starting the dig
    print("Sit back and relax. Digging takes a while...")
    print("DIgging...")

    # declarations
    fname = []
    matches = []

    # hash regex declarations
    re_list = [
    r'[a-f0-9]{4}',
    r'[a-f0-9]{8}',
    r'[a-f0-9]{6}',
    r'(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}',
    r'\+[a-z0-9\/.]{12}',
    r'[a-z0-9\/.]{13}',
    r'[a-f0-9]{16}',
    r'[a-z0-9\/.]{16}',
    r'\([a-z0-9\/+]{20}\)',
    r'_[a-z0-9\/.]{19}',
    r'[a-f0-9]{24}',
    r'[a-z0-9\/.]{24}',
    r'(\$md2\$)?[a-f0-9]{32}',
    r'[a-f0-9]{32}(:.+)?',
    r'(\$snefru\$)?[a-f0-9]{32}',
    r'(\$NT\$)?[a-f0-9]{32}',
    r'([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?',
    r'([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}',
    r'{SHA}[a-z0-9\/+]{27}=',
    r'\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?',
    r'0x[a-f0-9]{32}',
    r'\$H\$[a-z0-9\/.]{31}',
    r'\$P\$[a-z0-9\/.]{31}',
    r'[a-f0-9]{32}:[a-z0-9]{2}',
    r'\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}',
    r'{smd5}[a-z0-9$\/.]{31}',
    r'[a-f0-9]{32}:[a-f0-9]{32}',
    r'[a-f0-9]{32}:.{5}',
    r'[a-f0-9]{32}:.{8}',
    r'[a-z0-9]{34}',
    r'[a-f0-9]{40}(:.+)?',
    r'\*[a-f0-9]{40}',
    r'[a-z0-9]{43}',
    r'{SSHA}[a-z0-9\/+]{38}==',
    r'[a-z0-9=]{47}',
    r'[a-f0-9]{48}',
    r'[a-f0-9]{51}',
    r'[a-z0-9]{51}',
    r'{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}',
    r'0x0100[a-f0-9]{48}',
    r'(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}',
    r'[a-f0-9]{56}',
    r'(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}',
    r'[a-f0-9]{40}:[a-f0-9]{16}',
    r'(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}',
    r'\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}',
    r'[a-f0-9]{32}:.{3}',
    r'[a-f0-9]{32}:.{30}',
    r'(\$snefru\$)?[a-f0-9]{64}',
    r'[a-f0-9]{64}(:.+)?',
    r'[a-f0-9]{32}:[a-z0-9]{32}',
    r'[a-f-0-9]{32}:[a-f-0-9]{32}',
    r'(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?',
    r'\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}',
    r'{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}',
    r'[a-f0-9]{80}',
    r'\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}',
    r'0x0100[a-f0-9]{88}',
    r'[a-f0-9]{96}',
    r'{SSHA512}[a-z0-9\/+]{96}',
    r'{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}',
    r'[a-f0-9]{128}(:.+)?',
    r'[a-f0-9]{136}',
    r'0x0200[a-f0-9]{136}',
    r'\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}',
    r'[a-f0-9]{256}',
    r'grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}',
    r'sha1\$[a-z0-9]+\$[a-f0-9]{40}',
    r'[a-f0-9]{49}',
    r'\$S\$[a-z0-9\/.]{52}',
    r'\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}',
    r'0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}',
    r'\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}',
    r'\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})',
    r'sha256\$[a-z0-9]+\$[a-f0-9]{64}',
    r'sha384\$[a-z0-9]+\$[a-f0-9]{96}',
    r'crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}',
    r'[a-f0-9]{112}',
    r'[a-f0-9]{1329}',
    r'[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}',
    r'([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+',
    r'\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}',
    r'\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}',
    r'[a-f0-9]{40}:[a-f0-9]{0,32}',
    r'(.+)?\$[a-f0-9]{16}',
    r'(.+)?\$[a-f0-9]{40}',
    r'(.+\$)?[a-z0-9\/.+]{30}(:.+)?',
    r'0x[a-f0-9]{60}\s0x[a-f0-9]{40}',
    r'[a-f0-9]{40}:[^*]{1,25}',
    r'(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}',
    r'[a-f0-9]{130}(:[a-f0-9]{40})?',
    r'[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+',
    r'[a-z0-9\/.]{16}([:$].{1,})?',
    r'\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}',
    r'[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?',
    r'(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}',
    r'\$3\$\$[a-f0-9]{32}',
    r'\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}',
    r'[a-f0-9]{70}',
    r'[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}',
    r'[a-f0-9]{140}',
    r'\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}',
    r'\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}',
    r'\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}',
    r'\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=',
    r'\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}',
    r'{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+',
    r'\$PHPS\$.+\$[a-f0-9]{32}',
    r'[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}',
    r'[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}',
    r'[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}',
    r'[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}',
    r'[a-z0-9\/+]{27}=',
    r'crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}',
    r'(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}',
    r'pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}',
    r'bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}',
    r'md5\$[a-f0-9]+\$[a-f0-9]{32}',
    r'\{PKCS5S2\}[a-z0-9\/+]{64}',
    r'md5[a-f0-9]{32}',
    r'\([a-z0-9\/+]{49}\)',
    r'SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}',
    r'\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}',
    r'\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}',
    r'\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}',
    r'\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}',
    r'\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}',
    r'\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}',
    r'\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}',
    r'\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}',
    r'(\$radmin2\$)?[a-f0-9]{32}',
    r'{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+',
    r'\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}',
    r'[a-f0-9]{16}:2:4:[a-f0-9]{32}',
    r'[a-f0-9]{4,}',
    r'[a-z0-9\/.]{13,}',
    r'(\$cisco4\$)?[a-z0-9\/.]{43}',
    r'bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}',
    r'\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}',
    r'\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}',
    r'(\$pst\$)?[a-f0-9]{8}',
    r'sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}',
    r'(\$dahua\$)?[a-z0-9]{8}',
    r'\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}',
    r'\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}',
    ]


    # adds user custom regex to re_list
    if(args['regex'] != None):
        print("\nCustom regex line specified: Adding to regex object compilation!")
        re_list.append(args['regex'])
    else:
        pass


    # compile all the regex
    generic_re = re.compile('|'.join(re_list))
        

    # initial path to start recursive search
    path = args['directory']


    # appending full path of files to fname array
    for root, d_name, f_names in os.walk(path):
        for f in f_names:
            fname.append(os.path.join(root, f))


    # keeps track of files dug
    counter = 0

    # opens each file and checks for hash
    for i in fname:

        try:
            file = open(i, mode = 'r', encoding = 'utf-8-sig') 
            lines = file.readlines()
            file.close()

            # prints file being digged
            counter += 1
            print("Files dug: " + str(counter) + " ", end = '\r')
            sys.stdout.flush()

            # regex matches for the hashes
            for line in lines:
                matchArr = re.findall(generic_re, line)

                # cleaning array of empty false matches
                for item in matchArr:
                    for x in item:
                        if (x != ''):
                            matches += x

                            # prints hashes if vebose flag is set
                            if(args['verbose'] != None):
                                print(x)


        except:
            # nothing needs to be done file is not readable by UTF-8
            pass


    # string to which output will be saved
    output = "OUT:  \n"

    # print the found hashes
    for match in matches:
        output += match


    # prints either to stdout or specified output file
    if(args['output'] != None):
        #print to output file
        try:
            file = open(args['output'], 'w')
            file.write(output)
            file.close()
            exit()

        except: 
            print("\nERROR: Ouput file specified was not found!")
            print("Check if file was properly created or named")
            exit()

    # if no ouput file specified print to terminal
    else:
        print(output)


if __name__ == "__main__":
    main()


