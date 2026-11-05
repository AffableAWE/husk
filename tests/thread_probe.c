#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 4

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int counter;

static void *worker(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&lock);
    counter++;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    pid_t child;
    int status = 0;
    int i;

    for (i = 0; i < THREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, NULL);
        if (rc != 0) {
            printf("pthread_create_failed=%d\n", rc);
            return 2;
        }
    }
    for (i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);
    printf("threads=%d counter=%d\n", THREADS, counter);

    child = fork();
    if (child < 0) {
        printf("fork_failed\n");
        return 3;
    }
    if (child == 0)
        _exit(7);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 7) {
        printf("child_status_failed\n");
        return 4;
    }
    printf("child_exit=%d\n", WEXITSTATUS(status));
    return 0;
}
