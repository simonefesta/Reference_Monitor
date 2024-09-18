#ifndef _RM_UTILS__
#define _RM_UTILS__

// Dichiarazione extern di RM per renderlo disponibile a tutti i file che includono questo header
//extern RM_info RM;

size_t my_min(size_t a , size_t b);

char *get_current_proc_path(void);

ssize_t read_content(char * path, char *buf, size_t buflen);
	
char *get_cwd(void);

int temporal_file(const char *str);

char * get_absolute_path_by_name(char *name);

char *custom_dirname(char *path);

#endif


