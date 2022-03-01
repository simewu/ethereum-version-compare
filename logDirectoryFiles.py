import os
import re
import sys


isCodeFileRe = r'(.*\.cpp|.*\.h|.*\.py|.*\.c|.*\.sh)'

# Send a command to the terminal
def terminal(cmd):
	return os.popen(cmd).read()

# Given a regular expression, list the directories that match it, and ask for user input
def selectDir(regex, subdirs = False):
	dirs = []
	if subdirs:
		for (dirpath, dirnames, filenames) in os.walk('.'):
			if dirpath[:2] == '.\\': dirpath = dirpath[2:]
			if bool(re.match(regex, dirpath)):
				dirs.append(dirpath)
	else:
		for obj in os.listdir(os.curdir):
			if os.path.isdir(obj) and bool(re.match(regex, obj)):
				dirs.append(obj)

	print()
	if len(dirs) == 0:
		print(f'No directories were found that match "{regex}"')
		print()
		return ''

	print('List of directories:')
	for i, directory in enumerate(dirs):
		print(f'  Directory {i + 1}  -  {directory}')
	print()

	selection = None
	while selection is None:
		try:
			i = int(input(f'Please select a directory (1 to {len(dirs)}): '))
		except KeyboardInterrupt:
			sys.exit()
		except:
			pass
		if i > 0 and i <= len(dirs):
			selection = dirs[i - 1]
	print()
	return selection

# List the files with a regular expression
def listFiles(regex, directory = '', subdirs = False):
	#path = os.path.join(os.curdir, directory)
	#return [os.path.join(path, file) for file in os.listdir(path) if os.path.isfile(os.path.join(path, file)) and bool(re.match(regex, file))]
	files = []
	if subdirs:
		for (dirpath, dirnames, filenames) in os.walk(directory):
			for file in filenames:
				path = os.path.join(dirpath, file)
				if path[:2] == '.\\': path = path[2:]
				if bool(re.match(regex, path)):
					files.append(path)
	else:
		for file in os.listdir(os.curdir):
			if os.path.isfile(file) and bool(re.match(regex, file)):
				files.append(file)
	return files

def listDirectories(regex, subdirs = False, reverse = True):
	dirs = []
	if subdirs:
		for (dirpath, dirnames, filenames) in os.walk('.'):
			if dirpath[:2] == '.\\': dirpath = dirpath[2:]
			if bool(re.match(regex, dirpath)):
				dirs.append(dirpath)
	else:
		for obj in os.listdir(os.curdir):
			if os.path.isdir(obj) and bool(re.match(regex, obj)):
				dirs.append(obj)

	dirs = sortDirectories(dirs)

	print()
	if len(dirs) == 0:
		print(f'No directories were found that match "{regex}"')
		print()
		return []

	if reverse:
		print(dirs)
		dirs.reverse()
		print(dirs)

	print('List of directories:')
	for i, directory in enumerate(dirs):
		print(f'  Directory {i + 1}  -  {directory}')
	print()
	return dirs

def sortDirectories(dirs):
	temp = {}
	for directory in dirs:
		num = 0
		match = re.match(r'[^0-9]*([0-9]+)[^0-9]*([0-9]+)[^0-9]*([0-9]+)', directory)
		if match is not None:
			num = 1000 * 1000 * int(match.group(1)) + 1000 * int(match.group(2)) + int(match.group(3))
		temp[directory] = num
	
	sortedDict = dict(sorted(temp.items(), key=lambda item: item[1]))
	sortedDirs = []
	for directory in sortedDict:
		sortedDirs.append(directory)

	return sortedDirs



def getFileSize(filePath):
	if filePath == '/dev/null': return 0
	return os.path.getsize(filePath)

def compareDirectories(prevVersionDirectory, directory):
	numAdditions = 0
	numRemovals = 0
	numFilesChanged = 0
	numFilesChangedBytes = 0
	numCodeAdditions = 0
	numCodeRemovals = 0
	numCodeFilesChanged = 0
	numCodeFilesChangedBytes = 0

	if prevVersionDirectory == '': return {
		'Additions': numAdditions,
		'Removals': numRemovals,
		'FilesChanged': numFilesChanged,
		'FilesChangedBytes': numFilesChangedBytes,
		'CodeAdditions': numCodeAdditions,
		'CodeRemovals': numCodeRemovals,
		'CodeFilesChanged': numCodeFilesChanged,
		'CodeFilesChangedBytes': numCodeFilesChangedBytes,
	}

	cmd = 'git --no-pager diff --no-index --minimal --numstat ' + prevVersionDirectory + ' ' + directory
	print(cmd)
	output = terminal(cmd)
	lines = output.split('\n')
	for line in lines:
		match = re.match(r'^([0-9]+|-)\s+([0-9]+|-)\s+(.+)', line)
		if match is None: continue

		additions = 0
		removals = 0
		try: # Accomodate the "-" (binary files, which we consider as 0 additions and 0 removals)
			additions = int(match.group(1))
		except: pass
		try:
			removals = int(match.group(2))
		except: pass

		numAdditions += additions
		numRemovals += removals
		numFilesChanged += 1

		# Example of path:
		# match.group(3) = "{go-ethereum-0.10.3 => go-ethereum-0.10.4}/src/qt/locale/go-ethereum_ru.ts"
		path = match.group(3).split('=>')[1].replace('}', '').strip()
		fileSize = getFileSize(path)
		numFilesChangedBytes += fileSize
		

		extension = os.path.splitext(match.group(3))[1]
		if re.match(isCodeFileRe, extension) is not None:
			numCodeAdditions += additions
			numCodeRemovals += removals
			numCodeFilesChanged += 1
			numCodeFilesChangedBytes += fileSize

	return {
		'Additions': numAdditions,
		'Removals': numRemovals,
		'FilesChanged': numFilesChanged,
		'FilesChangedBytes': numFilesChangedBytes,
		'CodeAdditions': numCodeAdditions,
		'CodeRemovals': numCodeRemovals,
		'CodeFilesChanged': numCodeFilesChanged,
		'CodeFilesChangedBytes': numCodeFilesChangedBytes,
	}


def getDirectoryStats(directory, prevVersionDirectory):
	files = listFiles('.', directory, True)
	filesSize = 0
	for file in files:
		filesSize += os.path.getsize(file)

	codeFiles = listFiles(isCodeFileRe, directory, True)
	codefilesSize = 0
	for file in codeFiles:
		codefilesSize += getFileSize(file)

	extensionsDict = {}
	for file in files:
		extension = os.path.splitext(file)[1]
		if extension not in extensionsDict:
			extensionsDict[extension] = 1
		else:
			extensionsDict[extension] += 1
	extensionsDict = dict(sorted(extensionsDict.items(), key=lambda item: item[1], reverse=True))

	extensions = ''
	for key in extensionsDict:
		if len(extensions):
			extensions += ', '
		extensions += key + ' (' + str(extensionsDict[key]) + ')'

	comparison = compareDirectories(prevVersionDirectory, directory)

	print(directory + ':')
	return {
		'Ethereum Version': directory,
		'Num all files': len(files),
		'Size all files (B)': filesSize,
		'Num code files (sol, go, c, js, java, h, cpp, sh, s, py)': len(codeFiles),
		'Size code files (B)': codefilesSize,
		'*': '*',
		'All line additions': str(comparison['Additions']),
		'All line removals': str(comparison['Removals']),
		'All files changed': str(comparison['FilesChanged']),
		'Ratio all files changed': str(comparison['FilesChanged'] / len(files)),
		'All changed bytes': str(comparison['FilesChangedBytes']),
		'Ratio all bytes changed': str(comparison['FilesChangedBytes'] / filesSize),
		'* ': '*',
		'Code line additions': str(comparison['CodeAdditions']),
		'Code line removals': str(comparison['CodeRemovals']),
		'Code files changed': str(comparison['CodeFilesChanged']),
		'Ratio code files changed': str(comparison['CodeFilesChanged'] / len(codeFiles)),
		'Code changed bytes': str(comparison['CodeFilesChangedBytes']),
		'Ratio code bytes changed': str(comparison['CodeFilesChangedBytes'] / codefilesSize),
		'*  ': '*',
		'File extenension histogram': extensions,
	}


dirs = listDirectories(r'go-ethereum-.*', False, False)

outputFileName = 'logDirectoryOutput.csv'
outputFile = open(outputFileName, 'w')
headerMade = False

prevVersionDirectory = ''

for directory in dirs:
	data = getDirectoryStats(directory, prevVersionDirectory)
	if not headerMade:
		header = ''
		for key in data:
			header += '"' + key.strip() + '",'
		outputFile.write(header + '\n')
		headerMade = True

	line = ''
	for key in data:
		line += '"' + str(data[key]) + '",'
	outputFile.write(line + '\n')

	prevVersionDirectory = directory


print('Successfully wrote to "' + outputFileName + '".')