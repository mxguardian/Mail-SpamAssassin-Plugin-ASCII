# Internal Tools

This directory contains tools that are used internally by the project.

## `unicode.pl`

This script is used to generate the `unicode_db` database and find ascii equivalents. The basic steps are:

1. Run `unicode.pl create_schema` to create the required tables.
2. Run `unicode.pl import_ucd` to import the unicode database from unicode.org.
3. Run `unicode.pl import_confusables` to import the confusables database from unicode.org. You need to manually resolve any conflicts.
4. Run `unicode.pl decompose` to decompose characters into their constituent parts.
5. Run `unicode.pl list_homoglyphs` to list all homoglyphs and their ascii equivalents.
6. Visually inspect the output of `list_homoglyphs` and make any corrections to the `ascii` column.
7. Run `unicode.pl list_homoglyphs` again to verify that all glyphs are correctly mapped.
8. Run `unicode.pl generate_map` to generate the character map used in the `ASCII.pm` module.
9. Run `unicode.pl test_map` to run a simple test to verify that the map is correct.