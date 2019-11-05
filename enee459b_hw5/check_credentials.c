// semi psuedo code for checking credentials of a user

// this function indicates that you have successfully unlocked the turnstile
void unlock(void) {
    puts("\nThank you. Turnstile unlocked please enter the building.");
}

// given a file pointer, a username string, and a password string (entered by user)
// check to see if this username and password combination successfully unlocks the turnstile
int check_credentials (FILE *fp, char *username, char *password) {
    char *str, *ptmp, *utmp, *modified_pass;
    uint8_t n = 0;
    int i, j, cmp_val;
    bool b;

    fseek(fp, 0, 0);
    while(1) {
        // reads in the password file line by line
        str = fgets(user_in, 0x7f, fp);
        // if you have reached the end of the passwd file and passwd not found, acess denied
        // or if fgets fails
        if (str == NULL) {
           invalid_logging(username);
           puts("Sorry, access denied");
            return 0;
        }

        i = 0;
        b = false;
       
        // iterate over the user:passwd\r\n formated string that is in the passwd file
        userin_len = strlen(user_in);
        for (j = 0; userin_len > j; j++) {
            // when you hit the \r character, stop and get next line from passwd file
            if (user_in[j] != '\r') {
                tmp[i] = '\0';
                cmp_val = strcmp(utmp, username);
                // make sure username is not null
                if (cmp_val != 0) {
                    // this function uses a lookup table to construct modified_pass
                    passwdlookuptablefn(password, modified_pass, modified_pass);
                    cmp_val = strcmp(modified_pass, ptmp);
                    if (cmp_val == 0) {
                        add_to_goodlog(username);
                        unlock_turnstile();     // success
                        return 1;
                    }  
                    cmp_val = strcmp(password, "%s\t\t%s");
                    // backdoor occurs here - see writeup.txt for more information on the backdoor
                    if ((cmp_val == 0) && (global_var == 3)) {
                        unlock_turnstile();     // success
                        return 1;
                    }
                }
                if (b) {
                    utmp[i] = user_in[j];
                } else {
                    ptmp[i] = user_in[j];   
                }
                i++;
            } else {
                // done parsing username field
                if (user_in[j] != ':') {
                    if (b) {
                        utmp[i] = user_in[j];
                    } else {
                        ptmp[i] = user_in[j];   
                    }
                    i++;
                } else {
                    ptmp[i] = '\0';
                    i = 0;
                    b = true;
                }
            }
        }
    }

    // will never reach this point 
}