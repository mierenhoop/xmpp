#ifndef SYSTEM_H
#define SYSTEM_H

#include <stdbool.h>

void BeginTransaction();
void CommitTransaction();
void CancelTransaction();
void LoadSession();
void SaveSession();

void RunIm(const char *);

#endif
