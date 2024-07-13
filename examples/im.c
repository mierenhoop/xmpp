#include <sqlite3.h>
#include <stddef.h>
#include <assert.h>

#define DB_FILE "../o/im.db"

static sqlite3 *db;

int main() {
  int rc = sqlite3_open(DB_FILE, &db);
  assert(rc == SQLITE_OK);

  rc = sqlite3_exec(db, "create table if not exists message(id, body)", NULL, NULL, NULL);
  assert(rc == SQLITE_OK);
}
