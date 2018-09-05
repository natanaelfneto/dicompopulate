import os

files = []
i = 0

for root, dirs, files in os.walk('D:/PACS/'):
    if files:
        for file in files:
            file_path = os.path.abspath(os.path.join(root, file))
            print("Sending "+file_path)
            command = "dcmsnd DCM4CHEE@10.3.224.22:11112 "+file_path
            os.system(command)
            break

print('End')