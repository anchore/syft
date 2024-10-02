import os
import zipfile
import io

ARCHIVE_EXTENSIONS = ('.jar', '.war', '.ear', '.hpi', '.war', '.sar', '.nar', '.par')
METADATA_FILES = ('pom.xml', 'pom.properties', 'MANIFEST.MF')


def slim_archive(archive, output_dir, base_path="", archive_name=""):
    """
    extracts metadata files from the archive and creates a slim JAR file
    containing only these files. handles nested JARs by preserving them.
    """
    slim_buffer = io.BytesIO()
    with zipfile.ZipFile(archive, 'r') as zip_file:
        with zipfile.ZipFile(slim_buffer, 'w', zipfile.ZIP_DEFLATED) as slim_zip:
            for file_name in zip_file.namelist():
                # check for metadata files or nested JARs
                if file_name.endswith(METADATA_FILES):
                    # add metadata files directly to the slimmed archive
                    file_data = zip_file.read(file_name)
                    slim_zip.writestr(file_name, file_data)
                elif file_name.endswith(ARCHIVE_EXTENSIONS):
                    # if it's a nested archive, recursively slim it
                    nested_archive = io.BytesIO(zip_file.read(file_name))
                    nested_slim_buffer = io.BytesIO()
                    slim_archive(
                        nested_archive,
                        nested_slim_buffer,
                        base_path=os.path.join(base_path, os.path.dirname(file_name)),
                        archive_name=os.path.basename(file_name)
                    )
                    # add the slimmed nested archive back to the parent archive
                    nested_slim_buffer.seek(0)
                    slim_zip.writestr(file_name, nested_slim_buffer.read())

    # write out the slimmed JAR to the output directory if output_dir is a directory
    if isinstance(output_dir, str):
        output_path = os.path.join(output_dir, base_path, archive_name)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            slim_buffer.seek(0)
            f.write(slim_buffer.read())
    else:
        # if output_dir is a BytesIO buffer (for nested archives), just write to it
        output_dir.seek(0)
        output_dir.write(slim_buffer.getvalue())


def walk_directory_and_slim_jars(base_dir, output_dir):
    """
    recursively walks through a directory tree looking for .jar, .war, .ear,
    .hpi files and slims them down by keeping only metadata files.
    """
    for dirpath, _, filenames in os.walk(base_dir):
        for filename in filenames:
            if filename.endswith(ARCHIVE_EXTENSIONS):
                archive_path = os.path.join(dirpath, filename)
                print(f"Processing {archive_path}")
                slim_archive(archive_path, output_dir, os.path.relpath(dirpath, base_dir), filename)


# a helper script for slimming down JAR files by keeping only metadata files but still keeping the jar packaging,
# including nested JARs! Useful for testing purposes.
if __name__ == "__main__":
    BASE_DIR = "."
    OUTPUT_DIR = "./slim"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    walk_directory_and_slim_jars(BASE_DIR, OUTPUT_DIR)
