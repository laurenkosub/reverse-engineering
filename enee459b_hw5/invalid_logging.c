// incorrect entries are stored in /etc/badlog
int badlog(char *username) {    // rdi = username
    file *fp;
    time_t t;
    char *ct, *path = "/etc/badlog";
    // some global var = 0;
    global_var= 0;
    home = getenv("HOME");
    hlen = strlen(home);
    plen = strlen(path);
    if (plen + hlen < 0x40) {
        strncat(home, path, plen);
        fp = fopen(home, "a");
        if (fp != NULL) {
            time(&t);
            ct = ctime(&t);
            fprintf(fp, "%s\t\t%s", username,ct);
            fclose(fp);
        }
    } else {
        puts("Error in badlog path");
    }
}