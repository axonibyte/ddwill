# Usage

Usage: `ddwill <command> [options...]`

**Commands**

| Command             | Description                                             |
|---------------------|---------------------------------------------------------|
| [encrypt](#encrypt) | Encrypt the plaintext and split it up for distribution. |
| [decrypt](#decrypt) | Decrypt the ciphertext and recover the will.            |
| [info](#info)       | Provide information about a particular file.            |
| [help](#help)       | Print a potentially-helpful message.                    |

**Global Options**

These options can be used on all commands.

| Option        | Description                          |
|---------------|--------------------------------------|
| -h, --help    | Print a potentially-helpful message. |
| -V, --version | Print the software version.          |

All commands exit 0 on success, 1 if the operation failed (for example, not
enough shards to decrypt), and 2 for bad arguments.

## Encrypt

Use this command to encrypt your file.

Usage: `ddwill encrypt <options...>`

**Options**

| Option                  | Description                                                                   |
|-------------------------|-------------------------------------------------------------------------------|
| --infile <file>         | Required. The input file.                                                     |
| --outdir <dir>          | Required. The output directory.                                               |
| --canaries <count>      | Required, minimum of 0. The number of canaries to use for encryption.         |
| --trustees <count>      | Required, minimum of 2. The number of trustees shards will be given to.       |
| --quorum <count>        | Required, minimum of 2. The minimum number of shards required for decryption. |
| --description <message> | Optional message to be included that won't be encrypted.                      |
| --no-codes              | Skip per-shard recovery codes; each shard file alone is then the whole share. |

Unless `--no-codes` is given, every shard is locked with a **recovery code**
printed to stdout once (and stored nowhere). Write each code down and deliver
it to its trustee separately from the shard file -- different channel,
different time. A locked shard file without its code contributes nothing but
already-encrypted ciphertext, so a CD lost in the mail or found in a drawer is
useless on its own. Decryption then needs a quorum of shard files *and* their
codes.

## Decrypt

Use this command to decrypt your file.

Usage: `ddwill decrypt <options..>`

**Options**

| Options          | Description                                             |
|------------------|---------------------------------------------------------|
| --indir <dir>    | Required. The directory containing canaries and shards. |
| --outfile <file> | Required. The output file.                              |
| --code <code>    | Recovery code for a locked shard; repeat once per code. |

Codes are matched to shards by the leading number (`3-XXXX-...` belongs to
`shard_3.will`). Case, spacing, and the usual look-alikes (`O`/`0`, `I`/`L`/`1`)
are forgiven.

## Info

Use this command to give you more information about a file you've got. If it's a
canary or shard, print a readout of details that can be gleaned from the file,
along with a description (if one was provided).

Usage: `ddwill info <options...>`

**Options**

| Options         | Description                                   |
|-----------------|-----------------------------------------------|
| --infile <file> | Required. The file that you're curious about. |

## Help

Use this command for help on the command line.

Usage: `ddwill help [command]`
