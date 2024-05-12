#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_SIZE 1024

struct data {
  int pid; // Process ID
  int fd;  // File Descriptor
  char *filename;
  unsigned long inode;
  struct data *next;
};

// function used to allocate memory, create a new data CDT and/or insert a node
// to data
void createAndInsertAtEnd(struct data **head, int pid, int fd, char *filename,
                          unsigned long inode) {
  struct data *newNode = (struct data *)malloc(sizeof(struct data));
  // error handling
  if (newNode == NULL) {
    perror("Memory allocation failed for new node");
    return;
  }

  newNode->pid = pid;
  newNode->fd = fd;
  newNode->filename = strdup(filename); // need to free this after
  newNode->inode = inode;
  newNode->next = NULL;

  if (*head == NULL) {
    *head = newNode;
  } else {
    // if head exists, travserse to the end of the list and insert the newNode
    struct data *curr = *head;
    while (curr->next != NULL) {
      curr = curr->next;
    }
    curr->next = newNode;
  }
}

int has_user_permission(const char *path) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) {
    // perror("Failed to get file stats");
    return 0; // Indicate "no permission" or "unable to verify"
  }
  return statbuf.st_uid == getuid();
}

void getInfo(struct data **head) {
  DIR *proc_dir;
  struct dirent *proc_entry;
  char proc_path[MAX_SIZE], fd_path[MAX_SIZE], fd_link_path[MAX_SIZE],
      fdinfo_path[MAX_SIZE];
  char target_path[MAX_SIZE]; // Buffer

  proc_dir = opendir("/proc");
  if (!proc_dir) {
    perror("Failed to open /proc directory");
    exit(EXIT_FAILURE);
  }

  while ((proc_entry = readdir(proc_dir)) != NULL) {
    if (atoi(proc_entry->d_name) >
        0) { // Check if directory name is numeric (thus a PID)
      snprintf(proc_path, sizeof(proc_path), "/proc/%d",
               atoi(proc_entry->d_name)); // proc_path = 'proc/[PID]'

      snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/status",
               atoi(proc_entry->d_name));
      // permission checking
      if (has_user_permission(fdinfo_path) == 0 ||
          atoi(proc_entry->d_name) <= 0) {
        // If stat fails or the process does not belong to the current user,
        // skip this entry
        continue;
      }

      snprintf(fd_path, sizeof(fd_path) * 2, "%s/fd", proc_path);
      DIR *fd_dir = opendir(fd_path);
      if (!fd_dir) {
        continue; // Skip if unable to open the FD directory
      }

      struct dirent *fd_entry;
      while ((fd_entry = readdir(fd_dir)) != NULL) {
        if (strcmp(fd_entry->d_name, ".") != 0 &&
            strcmp(fd_entry->d_name, "..") != 0) {
          snprintf(fd_link_path, sizeof(fd_link_path) * 2, "%s/%s", fd_path,
                   fd_entry->d_name);
          ssize_t len =
              readlink(fd_link_path, target_path, sizeof(target_path) - 1);
          if (len != -1) {
            target_path[len] = '\0'; // Ensure null termination

            struct stat file_stat;
            if (stat(fd_link_path, &file_stat) ==
                0) { // Successfully got the file info

              createAndInsertAtEnd(head, atoi(proc_entry->d_name),
                                   atoi(fd_entry->d_name), target_path,
                                   file_stat.st_ino);
            }
          }
        }
      }
      closedir(fd_dir);
    }
  }
  closedir(proc_dir);
}

void cleanUp(struct data **head) {

  struct data *current = *head;
  struct data *next;

  while (current != NULL) {
    next = current->next;
    free(current->filename);
    free(current);
    current = next;
  }
  *head = NULL;
}

void printComposite(struct data *head, int pid) {
  struct data *current_head = head;

  printf("\t\tPID\tFD\tFilename\tInode "
         "\n\t\t===============================================\n");
  int i = 0;
  while (current_head != NULL) {
    {
      if (pid == 0) {
        printf("%d\t\t%d \t%d \t%s \t%ld\n", i, current_head->pid,
               current_head->fd, current_head->filename, current_head->inode);
      }
      if (current_head->pid == pid) {
        printf("\t\t%d \t%d \t%s \t%ld\n", current_head->pid, current_head->fd,
               current_head->filename, current_head->inode);
      }
    }
    i++;
    current_head = current_head->next;
  }
  printf("\t\t===============================================\n");
}

void printPerProcess(struct data *head, int pid) {
  struct data *current_head = head;
  printf("\t\tPID\tFD \n\t\t============\n");

  while (current_head != NULL) {
    {
      if (pid == 0 || current_head->pid == pid) {
        printf("\t\t%d \t%d\n", current_head->pid, current_head->fd);
      }
    }
    current_head = current_head->next;
  }
  printf("\t\t============\n");
}

void printSystemWide(struct data *head, int pid) {
  struct data *current_head = head;

  printf("\t\tPID\tFD\tFilename "
         "\n\t\t===============================================\n");

  while (current_head != NULL) {
    {
      if (pid == 0 || current_head->pid == pid) {
        printf("\t\t%d \t%d \t%s\n", current_head->pid, current_head->fd,
               current_head->filename);
      }
    }
    current_head = current_head->next;
  }
  printf("\t\t===============================================\n");
}

void printVNodes(struct data *head, int pid) {
  struct data *current_head = head;

  printf("\t\tFD\t\tInode "
         "\n\t\t===============================================\n");

  while (current_head != NULL) {
    {
      if (pid == 0 || current_head->pid == pid) {
        printf("\t\t%d \t\t%ld\n", current_head->fd, current_head->inode);
      }
    }
    current_head = current_head->next;
  }
  printf("\t\t===============================================\n");
}

void printThreshold(struct data *head, int threshold) {
  struct data *current_head = head;

  printf("## Offending processes -- #FD Threshold=%d \n", threshold);

  while (current_head != NULL) {
    if (current_head->fd > threshold) {
      printf("%d (%d),", current_head->pid, current_head->fd);
    }
    current_head = current_head->next;
  }
}

void saveCompositeAsText(struct data *head, const char *filename, int pid) {
  // Open file for writing
  FILE *file = fopen(filename, "w");
  if (file == NULL) {
    perror("Failed to open file");
    return;
  }

  struct data *current_head = head;

  fprintf(file, "\t\tPID\tFD\tFilename\tInode "
                "\n\t\t===============================================\n");
  int i = 0;
  while (current_head != NULL) {
    {
      if (pid == 0) {
        fprintf(file, "%d\t\t%d \t%d \t%s \t%ld\n", i, current_head->pid,
                current_head->fd, current_head->filename, current_head->inode);
      }
      if (current_head->pid == pid) {
        fprintf(file, "\t\t%d \t%d \t%s \t%ld\n", current_head->pid,
                current_head->fd, current_head->filename, current_head->inode);
      }
    }
    i++;
    current_head = current_head->next;
  }
  fprintf(file, "\t\t===============================================\n");

  fclose(file);
}

void saveCompositeAsBinary(struct data *head, const char *filename, int pid) {
  // Open file for binary writing using wb
  FILE *file = fopen(filename, "wb");
  if (file == NULL) {
    // error handling
    perror("Failed to open file");
    return;
  }

  struct data *current_head = head;

  while (current_head != NULL) {
    if (pid == 0 || current_head->pid == pid) {
      fwrite(&current_head->pid, sizeof(current_head->pid), 1, file);
      fwrite(&current_head->fd, sizeof(current_head->fd), 1, file);

      // get the length of the filename string, and +1 for null terminator
      size_t len = strlen(current_head->filename) + 1;

      // write length of filename
      fwrite(&len, sizeof(len), 1, file);

      // write filename itself
      fwrite(current_head->filename, len, 1, file);

      fwrite(&current_head->inode, sizeof(current_head->inode), 1, file);
    }
    current_head = current_head->next;
  }
  fclose(file);
}

int main(int argc, char *argv[]) {
  // define flags for the arguments

  int composite = 0;
  int per_process = 0;
  int system_wide = 0;
  int v_node = 0;
  int threshold = -1;
  int output_txt = 0;
  int output_bi = 0;

  int pid = 0; // default is 0, means print all processes

  struct data *head = NULL;

  getInfo(&head);
  struct data *current_head = head;

  if (argc == 1) {
    // No arguments were provided other than the program name so only print
    // composite table
    printComposite(current_head, pid);
    cleanUp(&head);
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--per-process") == 0) {
      per_process = 1;
    } else if (strcmp(argv[i], "--systemWide") == 0) {
      system_wide = 1;
    } else if (strcmp(argv[i], "--Vnodes") == 0) {
      v_node = 1;
    } else if (strcmp(argv[i], "--composite") == 0) {
      composite = 1;
    } else if (strncmp(argv[i], "--threshold=", 12) == 0) {
      threshold = atoi(argv[i] + 12);
    } else if (isdigit(argv[i][0])) {
      // Assuming this is the PID
      pid = atoi(argv[i]);
    } else if (strcmp(argv[i], "--output_TXT") == 0) {
      output_txt = 1;
    } else if (strcmp(argv[i], "--output_binary") == 0) {
      output_bi = 1;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      cleanUp(&head);
      return 1;
    }
  }
  if (pid > 0) {
    printf("target PID is: %d \n", pid);
  }

  // handling the case where only pid is put in
  if (pid > 0 && !(composite) && !(per_process) && !(system_wide) &&
      !(v_node)) {
    // print all
    printPerProcess(current_head, pid);
    printSystemWide(current_head, pid);
    printVNodes(current_head, pid);
    printComposite(current_head, pid);
  }

  // if only threshold is called, print all, then return
  if (threshold >= 0 && argc == 2) {
    // print all
    printPerProcess(current_head, pid);
    printSystemWide(current_head, pid);
    printVNodes(current_head, pid);
    printComposite(current_head, pid);
    printThreshold(current_head, threshold);
    cleanUp(&head);
    return 0;
  }

  if (per_process) {
    printPerProcess(current_head, pid);
  }

  if (system_wide) {
    printSystemWide(current_head, pid);
  }

  if (v_node) {
    printVNodes(current_head, pid);
  }

  if (composite) {
    printComposite(current_head, pid);
  }

  // will be printed regardless of PID
  if (threshold >= 0) {
    printThreshold(current_head, threshold);
  }

  if (output_txt) {
    saveCompositeAsText(current_head, "compositeTable.txt", pid);
  }

  if (output_bi) {
    saveCompositeAsBinary(current_head, "compositeTable.bin", pid);
  }

  cleanUp(&head);
  return 0;
}