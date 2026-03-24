#include "runner.h"
#include <dirent.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Load entire file into malloc'd string */
static char *load_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t len, nread;
    char *buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    nread = fread(buf, 1, len, f);
    if (nread != len) { free(buf); fclose(f); return NULL; }
    buf[len] = '\0';
    fclose(f);
    return buf;
}

/* Load and parse JSON file */
static cJSON *load_json(const char *path)
{
    char *text = load_file(path);
    cJSON *root;
    if (!text) return NULL;
    root = cJSON_Parse(text);
    free(text);
    return root;
}

static const runner_def_t runners[] = {
    { "aead_test_schema_v1.json",               run_aead },
    { "mac_test_schema_v1.json",                 run_mac },
    { "hkdf_test_schema_v1.json",                run_hkdf },
    { "ind_cpa_test_schema_v1.json",             run_ind_cpa },
    { "keywrap_test_schema_v1.json",             run_keywrap },
    { "ecdh_test_schema_v1.json",                run_ecdh },
    { "ecdsa_verify_schema_v1.json",             run_ecdsa },
    { "ecdsa_p1363_verify_schema_v1.json",       run_ecdsa_p1363 },
    { "eddsa_verify_schema_v1.json",             run_eddsa },
    { "xdh_comp_schema_v1.json",                 run_xdh },
    { "rsassa_pkcs1_verify_schema_v1.json",      run_rsa_sig },
    { "rsaes_oaep_decrypt_schema_v1.json",       run_rsa_oaep },
    { "rsassa_pss_verify_schema_v1.json",        run_rsa_pss },
    { NULL, NULL }
};

static runner_fn find_runner(const char *schema)
{
    int i;
    for (i = 0; runners[i].schema; i++) {
        if (strcmp(runners[i].schema, schema) == 0)
            return runners[i].run;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *wycheproof_dir = getenv("WYCHEPROOF_DIR");
    char vectors_dir[PATH_MAX];
    struct dirent **namelist;
    int n_files, i;
    int total_pass = 0, total_fail = 0, total_skip = 0;
    int files_tested = 0, files_skipped = 0;

    (void)argc; (void)argv;

    if (!wycheproof_dir)
        wycheproof_dir = WYCHEPROOF_DEFAULT;

    /* try testvectors_v1/ first, then testvectors/ */
    snprintf(vectors_dir, sizeof(vectors_dir), "%s/testvectors_v1", wycheproof_dir);
    n_files = scandir(vectors_dir, &namelist, NULL, alphasort);
    if (n_files < 0) {
        snprintf(vectors_dir, sizeof(vectors_dir), "%s/testvectors", wycheproof_dir);
        n_files = scandir(vectors_dir, &namelist, NULL, alphasort);
    }
    if (n_files < 0) {
        fprintf(stderr, "Cannot open %s/testvectors_v1/ or testvectors/\n",
                wycheproof_dir);
        return 2;
    }

    printf("wychcheck: testing wolfSSL against Wycheproof vectors\n");
    printf("vectors: %s\n\n", vectors_dir);

    for (i = 0; i < n_files; i++) {
        char path[PATH_MAX];
        cJSON *root = NULL, *schema_item;
        runner_fn run;
        test_result_t r;
        size_t nlen = strlen(namelist[i]->d_name);

        if (nlen < 6 || strcmp(namelist[i]->d_name + nlen - 5, ".json") != 0)
            goto next;

        snprintf(path, sizeof(path), "%s/%s", vectors_dir, namelist[i]->d_name);

        root = load_json(path);
        if (!root) {
            files_skipped++;
            goto next;
        }

        schema_item = cJSON_GetObjectItem(root, "schema");
        if (!schema_item || !cJSON_IsString(schema_item)) {
            files_skipped++;
            goto next;
        }

        run = find_runner(schema_item->valuestring);

        if (!run) {
            files_skipped++;
            goto next;
        }

        r = run(root, namelist[i]->d_name);
        if (r.passed + r.failed + r.skipped == 0) {
            /* runner compiled out (feature disabled) */
            printf("SKIP  %-50s (not compiled)\n", namelist[i]->d_name);
            files_skipped++;
        } else if (r.failed == 0) {
            printf("PASS  %-50s %d passed, %d skipped\n",
                   namelist[i]->d_name, r.passed, r.skipped);
            files_tested++;
        } else {
            printf("FAIL  %-50s %d passed, %d FAILED, %d skipped\n",
                   namelist[i]->d_name, r.passed, r.failed, r.skipped);
            files_tested++;
        }

        total_pass += r.passed;
        total_fail += r.failed;
        total_skip += r.skipped;

    next:
        cJSON_Delete(root);
        free(namelist[i]);
    }
    free(namelist);

    printf("\n--- summary ---\n");
    printf("files tested: %d, skipped: %d\n", files_tested, files_skipped);
    printf("vectors: %d passed, %d failed, %d skipped\n",
           total_pass, total_fail, total_skip);

    return total_fail > 0 ? 1 : 0;
}
