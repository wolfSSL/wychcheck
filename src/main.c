#include "runner.h"
#include <dirent.h>
#include <sys/stat.h>

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

/* Extract "schema" field from JSON without full parse - quick peek */
static char *peek_schema(const char *json_path)
{
    cJSON *root = load_json(json_path);
    cJSON *s;
    char *schema = NULL;

    if (!root) return NULL;
    s = cJSON_GetObjectItem(root, "schema");
    if (s && cJSON_IsString(s))
        schema = strdup(s->valuestring);
    cJSON_Delete(root);
    return schema;
}

int main(int argc, char **argv)
{
    const char *wycheproof_dir = getenv("WYCHEPROOF_DIR");
    char vectors_dir[4096];
    DIR *dir;
    struct dirent *ent;
    int total_pass = 0, total_fail = 0, total_skip = 0;
    int files_tested = 0, files_skipped = 0;

    (void)argc; (void)argv;

    if (!wycheproof_dir) {
        fprintf(stderr, "Set WYCHEPROOF_DIR to a wycheproof repo checkout\n");
        return 2;
    }

    /* try testvectors_v1/ first, then testvectors/ */
    snprintf(vectors_dir, sizeof(vectors_dir), "%s/testvectors_v1", wycheproof_dir);
    dir = opendir(vectors_dir);
    if (!dir) {
        snprintf(vectors_dir, sizeof(vectors_dir), "%s/testvectors", wycheproof_dir);
        dir = opendir(vectors_dir);
    }
    if (!dir) {
        fprintf(stderr, "Cannot open %s/testvectors_v1/ or testvectors/\n",
                wycheproof_dir);
        return 2;
    }

    printf("wychcheck: testing wolfSSL against Wycheproof vectors\n");
    printf("vectors: %s\n\n", vectors_dir);

    while ((ent = readdir(dir)) != NULL) {
        char path[4096];
        char *schema;
        runner_fn run;
        test_result_t r;
        size_t nlen = strlen(ent->d_name);

        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".json") != 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", vectors_dir, ent->d_name);

        schema = peek_schema(path);
        if (!schema) {
            files_skipped++;
            continue;
        }

        run = find_runner(schema);
        free(schema);

        if (!run) {
            files_skipped++;
            continue;
        }

        r = run(path);
        if (r.passed + r.failed + r.skipped == 0) {
            /* runner compiled out (feature disabled) */
            printf("SKIP  %-50s (not compiled)\n", ent->d_name);
            files_skipped++;
        } else if (r.failed == 0) {
            printf("PASS  %-50s %d passed, %d skipped\n",
                   ent->d_name, r.passed, r.skipped);
            files_tested++;
        } else {
            printf("FAIL  %-50s %d passed, %d FAILED, %d skipped\n",
                   ent->d_name, r.passed, r.failed, r.skipped);
            files_tested++;
        }

        total_pass += r.passed;
        total_fail += r.failed;
        total_skip += r.skipped;
    }
    closedir(dir);

    printf("\n--- summary ---\n");
    printf("files tested: %d, skipped: %d\n", files_tested, files_skipped);
    printf("vectors: %d passed, %d failed, %d skipped\n",
           total_pass, total_fail, total_skip);

    return total_fail > 0 ? 1 : 0;
}
