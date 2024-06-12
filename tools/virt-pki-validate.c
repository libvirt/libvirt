/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "internal.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "virgettext.h"
#include "virfile.h"
#include "virnettlsconfig.h"
#include "virnettlscert.h"
#include "virutil.h"
#include "virt-validate-common.h"

static bool
virPKIValidateFile(const char *file,
                   uid_t owner,
                   gid_t group,
                   mode_t mode)
{
    struct stat sb;
    if (stat(file, &sb) < 0)
        return false;

    if (sb.st_uid != owner ||
        sb.st_gid != group)
        return false;

    return (sb.st_mode & 0777) == mode;
}

#define FILE_REQUIRE_EXISTS(scope, path, message, hint, ...) \
    do { \
      virValidateCheck(scope, "%s", message); \
      if (!virFileExists(path)) { \
          virValidateFail(VIR_VALIDATE_FAIL, hint, __VA_ARGS__); \
          ok = false; \
          goto done; \
      } else { \
          virValidatePass(); \
      } \
    } while (0)

#define FILE_REQUIRE_ACCESS(scope, path, message, uid, gid, mode, hint, ...) \
    do { \
        virValidateCheck(scope, "%s", message); \
        if (!virPKIValidateFile(path, uid, gid, mode)) { \
            virValidateFail(VIR_VALIDATE_FAIL, hint, __VA_ARGS__); \
            ok = false; \
        } else { \
            virValidatePass(); \
        } \
    } while (0)

static bool
virPKIValidateTrust(bool system, const char *path)
{
    g_autofree char *cacert = NULL, *cacrl = NULL;
    bool ok = true;

    if (system) {
        virNetTLSConfigSystemTrust(&cacert,
                                   &cacrl);

        FILE_REQUIRE_EXISTS("TRUST",
                            LIBVIRT_PKI_DIR,
                            _("Checking if system PKI dir exists"),
                            _("The system PKI dir %1$s is usually installed as part of the base filesystem or openssl packages"),
                            LIBVIRT_PKI_DIR);

        FILE_REQUIRE_ACCESS("TRUST",
                            LIBVIRT_PKI_DIR,
                            _("Checking system PKI dir access"),
                            0, 0, 0755,
                            _("The system PKI dir %1$s must be accessible to all users. As root, run: chown root.root; chmod 0755 %2$s"),
                            LIBVIRT_PKI_DIR, LIBVIRT_PKI_DIR);


        FILE_REQUIRE_EXISTS("TRUST",
                            LIBVIRT_CACERT_DIR,
                            _("Checking if system CA dir exists"),
                            _("The system CA dir %1$s is usually installed as part of the base filesystem or openssl packages"),
                            LIBVIRT_CACERT_DIR);

        FILE_REQUIRE_ACCESS("TRUST",
                            LIBVIRT_CACERT_DIR,
                            _("Checking system CA dir access"),
                            0, 0, 0755,
                            _("The system CA dir %1$s must be accessible to all users. As root, run: chown root.root; chmod 0755 %2$s"),
                            LIBVIRT_CACERT_DIR, LIBVIRT_CACERT_DIR);
    } else if (path) {
        virNetTLSConfigCustomTrust(path,
                                   &cacert,
                                   &cacrl);

        FILE_REQUIRE_EXISTS("TRUST",
                            path,
                            _("Checking if custom PKI base dir exists"),
                            _("Create the dir %1$s"),
                            path);

        FILE_REQUIRE_ACCESS("TRUST",
                            path,
                            _("Checking custom PKI base dir access"),
                            getuid(), getgid(), 0700,
                            _("The PKI base dir %1$s must not be accessible to other users. Run: chown %2$d.%3$d %4$s; chmod 0700 %5$s"),
                            path, getuid(), getgid(), path, path);
    } else {
        g_autofree char *pkipath = virNetTLSConfigUserPKIBaseDir();

        virNetTLSConfigUserTrust(&cacert,
                                 &cacrl);

        FILE_REQUIRE_EXISTS("TRUST",
                            pkipath,
                            _("Checking if user PKI base dir exists"),
                            _("Create the dir %1$s"),
                            pkipath);

        FILE_REQUIRE_ACCESS("TRUST",
                            pkipath,
                            _("Checking user PKI base dir access"),
                            getuid(), getgid(), 0700,
                            _("The PKI base dir %1$s must not be accessible to other users. Run: chown %2$d.%3$d %4$s; chmod 0700 %5$s"),
                            pkipath, getuid(), getgid(), pkipath, pkipath);
    }

    FILE_REQUIRE_EXISTS("TRUST",
                        cacert,
                        _("Checking if CA cert exists"),
                        _("The machine cannot act as a client or server. See https://libvirt.org/kbase/tlscerts.html#setting-up-a-certificate-authority-ca on how to install %1$s"),
                        cacert);

    if (system) {
        FILE_REQUIRE_ACCESS("TRUST",
                            cacert,
                            _("Checking CA cert access"),
                            0, 0, 0644,
                            _("The CA certificate %1$s must be accessible to all users. As root run: chown root.root %2$s; chmod 0644 %3$s"),
                            cacert, cacert, cacert);
    } else {
        FILE_REQUIRE_ACCESS("TRUST",
                            cacert,
                            _("Checking CA cert access"),
                            getuid(), getgid(), 0600,
                            _("The CA certificate %1$s must not be accessible to other users. As this user, run: chown %2$d.%3$d %4$s; chmod 0600 %5$s"),
                            cacert, getuid(), getgid(), cacert, cacert);
    }

 done:
    return ok;
}

static bool
virPKIValidateIdentity(bool isServer, bool system, const char *path)
{
    g_autofree char *cacert = NULL, *cacrl = NULL;
    g_autofree char *cert = NULL, *key = NULL;
    bool ok = true;
    const char *scope = isServer ? "SERVER" : "CLIENT";

    if (system) {
        virNetTLSConfigSystemTrust(&cacert,
                                   &cacrl);
        virNetTLSConfigSystemIdentity(isServer,
                                      &cert,
                                      &key);

        FILE_REQUIRE_EXISTS(scope,
                            LIBVIRT_CERT_DIR,
                            _("Checking if system cert dir exists"),
                            _("The system cert dir %1$s is usually installed as part of the libvirt package"),
                            LIBVIRT_CERT_DIR);

        FILE_REQUIRE_ACCESS(scope,
                            LIBVIRT_CERT_DIR,
                            _("Checking system cert dir access"),
                            0, 0, 0755,
                            _("The system cert dir %1$s must be accessible to all users. As root, run: chown root.root; chmod 0755 %2$s"),
                            LIBVIRT_CERT_DIR, LIBVIRT_CERT_DIR);

        FILE_REQUIRE_EXISTS(scope,
                            LIBVIRT_KEY_DIR,
                            _("Checking if system key dir exists"),
                            _("The system key dir %1$s is usually installed as part of the libvirt package"),
                            LIBVIRT_KEY_DIR);

        FILE_REQUIRE_ACCESS(scope,
                            LIBVIRT_KEY_DIR,
                            _("Checking system key dir access"),
                            0, 0, 0755,
                            _("The system key dir %1$s must be accessible to all users. As root, run: chown root.root; chmod 0755 %2$s"),
                            LIBVIRT_KEY_DIR, LIBVIRT_KEY_DIR);
    } else if (path) {
        virNetTLSConfigCustomTrust(path,
                                   &cacert,
                                   &cacrl);
        virNetTLSConfigCustomIdentity(path,
                                      isServer,
                                      &cert,
                                      &key);
    } else {
        virNetTLSConfigUserTrust(&cacert,
                                 &cacrl);
        virNetTLSConfigUserIdentity(isServer,
                                    &cert,
                                    &key);
    }

    FILE_REQUIRE_EXISTS(scope,
                        key,
                        _("Checking if key exists"),
                        isServer ?
                        _("The machine cannot act as a server. See https://libvirt.org/kbase/tlscerts.html#issuing-server-certificates on how to regenerate %1$s") :
                        _("The machine cannot act as a client. See https://libvirt.org/kbase/tlscerts.html#issuing-client-certificates on how to regenerate %1$s"),
                        key);

    if (system) {
        FILE_REQUIRE_ACCESS(scope,
                            key,
                            _("Checking key access"),
                            0, 0, isServer ? 0600 : 0644,
                            isServer ?
                            _("The server key %1$s must not be accessible to unprivileged users. As root run: chown root.root %2$s; chmod 0600 %3$s") :
                            _("The client key %1$s must be accessible to all users. As root run: chown root.root %2$s; chmod 0644 %3$s"),
                            key, key, key);
    } else {
        FILE_REQUIRE_ACCESS(scope,
                            key,
                            _("Checking key access"),
                            getuid(), getgid(), 0600,
                            isServer ?
                            _("The server key %1$s must be not be accessible to other users. As this user, run: chown %2$d.%3$d %4$s; chmod 0600 %5$s") :
                            _("The client key %1$s must be not be accessible to other users. As this user, run: chown %2$d.%3$d %4$s; chmod 0600 %5$s"),
                            key, getuid(), getgid(), key, key);
    }

    FILE_REQUIRE_EXISTS(scope,
                        cert,
                        _("Checking if cert exists"),
                        isServer ?
                        _("The machine cannot act as a server. See https://libvirt.org/kbase/tlscerts.html#issuing-server-certificates on how to regenerate %1$s") :
                        _("The machine cannot act as a client. See https://libvirt.org/kbase/tlscerts.html#issuing-client-certificates on how to regenerate %1$s"),
                        cert);

    if (system) {
        FILE_REQUIRE_ACCESS(scope,
                            cert,
                            _("Checking cert access"),
                            0, 0, 0644,
                            isServer ?
                            _("The server cert %1$s must be accessible to all users. As root run: chown root.root %2$s; chmod 0644 %3$s") :
                            _("The client cert %1$s must be accessible to all users. As root run: chown root.root %2$s; chmod 0644 %3$s"),
                            cert, cert, cert);
    } else {
        FILE_REQUIRE_ACCESS(scope,
                            cert,
                            _("Checking cert access"),
                            getuid(), getgid(), 0600,
                            isServer ?
                            _("The server cert %1$s must be restricted to this user. As this user, run: chown %2$d.%3$d %4$s; chmod 0600 %5$s") :
                            _("The client cert %1$s must be restricted to this user. As this user, run: chown %2$d.%3$d %4$s; chmod 0600 %5$s"),
                            cert, getuid(), getgid(), cert, cert);
    }

    virValidateCheck(scope, "%s", _("Checking cert properties"));

    if (virNetTLSCertSanityCheck(isServer,
                                 cacert,
                                 cert) < 0) {
        virValidateFail(VIR_VALIDATE_FAIL, "%s",
                        virGetLastErrorMessage());
        ok = false;
    } else {
        virValidatePass();
    }

    if (isServer) {
        gnutls_x509_crt_t crt;

        virValidateCheck(scope, "%s", _("Checking cert hostname match"));

        if (!(crt = virNetTLSCertLoadFromFile(cert, true))) {
            virValidateFail(VIR_VALIDATE_FAIL,
                            _("Unable to load %1$s: %2$s"),
                            cert, virGetLastErrorMessage());
        } else {
            g_autofree char *hostname = virGetHostname();
            int ret = gnutls_x509_crt_check_hostname(crt, hostname);
            gnutls_x509_crt_deinit(crt);
            if (!ret) {
                /* Only warning, since there can be valid reasons for mis-match */
                virValidateFail(VIR_VALIDATE_WARN,
                                _("Certificate %1$s owner does not match the hostname %2$s"),
                                cert, hostname);
                ok = false;
            } else {
                virValidatePass();
            }
        }
    }

 done:
    return ok;
}


static void
print_usage(const char *progname,
            FILE *out)
{
  fprintf(out,
          _("Usage:\n"
            "  %1$s { -v | -h } [TRUST|SERVER|CLIENT]\n"
            "\n"
            "Validate TLS certificate configuration\n"
            "\n"
            "options:\n"
            "  -s     | --system   validate system certificates (default)\n"
            "  -u     | --user     validate user certificates\n"
            "  -p DIR | --path DIR validate custom certificate path\n"
            "  -h     | --help     display this help and exit\n"
            "  -v     | --version  output version information and exit\n"),
          progname);
}

int main(int argc, char **argv)
{
    const char *scope = NULL;
    bool system = false;
    bool user = false;
    const char *path = NULL;
    bool quiet = false;
    int arg = 0;
    bool ok = true;
    const char *progname = argv[0];
    struct option opt[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'v' },
        { "system", no_argument, NULL, 's' },
        { "user", no_argument, NULL, 'u' },
        { "path", required_argument, NULL, 'p' },
        { NULL, 0, NULL, 0 },
    };

    if (virGettextInitialize() < 0)
        return EXIT_FAILURE;

    while ((arg = getopt_long(argc, argv, "hvsup:", opt, NULL)) != -1) {
        switch (arg) {
        case 's':
            system = true;
            break;

        case 'u':
            user = true;
            break;

        case 'p':
            path = optarg;
            break;

        case 'v':
            printf("%s\n", PACKAGE_VERSION);
            return EXIT_SUCCESS;

        case 'h':
            print_usage(progname, stdout);
            return EXIT_SUCCESS;

        case 'q':
            quiet = true;
            break;

        case '?':
        default:
            print_usage(progname, stderr);
            return EXIT_FAILURE;
        }
    }

    if ((argc - optind) > 2) {
        fprintf(stderr, _("%1$s: too many command line arguments\n"), argv[0]);
        print_usage(progname, stderr);
        return EXIT_FAILURE;
    }

    if (argc > 1)
        scope = argv[optind];

    virValidateSetQuiet(quiet);

    if ((system && user) ||
        (system && path) ||
        (user && path)) {
        g_printerr("--system, --user & --path are mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if (!system && !user && !path)
        system = true;

    if ((!scope || g_str_equal(scope, "trust")) &&
        !virPKIValidateTrust(system, path))
        ok = false;
    if ((!scope || g_str_equal(scope, "server")) &&
        !virPKIValidateIdentity(true, system, path))
        ok = false;
    if ((!scope || g_str_equal(scope, "client")) &&
        !virPKIValidateIdentity(false, system, path))
        ok = false;

    if (!ok)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
