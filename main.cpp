#include <iostream>
#include <fstream>
#include <vector>
#include "pin.H"

struct bin_part {
	unsigned long address; /* Address of data in remote binary */
	size_t size;           /* Size of data */
	uint8_t *data;         /* The actual data */
};

std::vector<struct bin_part> remote_bin_parts;

KNOB<std::string> knob_dump_file(KNOB_MODE_WRITEONCE, "pintool", "o", "unpacked.exe", "Dump file");

static void rebuild(void) {
	if (!remote_bin_parts.empty()) {
		std::ofstream file;

		file.open(knob_dump_file.Value().c_str(), std::ios::binary | std::ios::out);

		printf("Rebuilding binary just before ResumeThread()\n");
		for (auto bin = remote_bin_parts.begin(); bin != remote_bin_parts.end(); ++bin) {
			printf("Writing 0x%08X bytes of data at offset 0x%08X in file\n", bin->size, bin->address - 0x00400000);
			file.write((char*)bin->data, bin->size);
		}
	}
	/* That's plain lazy and the user has to manualy terminate the child process */
	/* But it works for now */
	printf("Terminating process before the child's thread is resumed, go ahead and kill it now\n");
	PIN_ExitProcess(1);
}

static void save_bytes(ADDRINT base_address, ADDRINT buffer, ADDRINT size) {
	if (size != 4) { // we skip the base address
		struct bin_part bin_part = { 0 };
		printf("arguments: 0x%08X, 0x%08X, 0x%08X\n", base_address, buffer, size);
		bin_part.data = (uint8_t*)malloc(size * sizeof(uint8_t));
		if (NULL == bin_part.data) {
			fprintf(stderr, "Out of memory\n");
			PIN_ExitProcess(1);
		}
		PIN_SafeCopy(bin_part.data, (void*)buffer, size);
		bin_part.size = size;
		bin_part.address = (unsigned long)base_address;
		remote_bin_parts.push_back(bin_part);
	}
}

static void createprocess_entry_handler(char *function_name, unsigned long process_creation_flag) {
	printf("Looking for creation flag in %s\n", function_name);
	if (0x4 != process_creation_flag) {
		fprintf(stderr, "Not suspended\n");
		PIN_ExitProcess(1);
	}
	printf("found CREATE_SUSPENDED flag\n");
}

static void instrument_image(IMG image, void *v) {
	/* Instrument function CreateProcess in order to check that the PE is started in suspended mode */
	const char *functions[] = { "CreateProcessW", "CreateProcessA" };
	std::string image_name = IMG_Name(image);

	if (0 == image_name.compare(image_name.size() - strlen("kernelbase.dll"), strlen("kernelbase.dll"), "KernelBase.dll")) {
		printf("Instrumenting image: %s\n", image_name.c_str());

		/* TODO: Maybe i should instrument IPOINT_AFTER in order to get process information and pid to kill the child after i'm done. */
		/*       Howerver, that would mean using PinCRT and that seems like a whole lot of trouble */
		/*       I would maybe have to look at IARG_FUNCRET_EXITPOINT_* but not quite sure right now */
		for (size_t i = 0; i <= 1; i++) { 
			const RTN routine = RTN_FindByName(image, functions[i]);
			if (RTN_Valid(routine)) {
				printf("Instrumenting %s\n", RTN_Name(routine).c_str());
				RTN_Open(routine);
				// Check the 5th argument, it must be CREATE_SUSPENDED
				RTN_InsertCall(routine, 
					IPOINT_BEFORE, (AFUNPTR)createprocess_entry_handler, 
					IARG_ADDRINT, RTN_Name(routine).c_str(),
					IARG_FUNCARG_ENTRYPOINT_VALUE, 5, 
					IARG_END
				);
				RTN_Close(routine);
			}
		}

		RTN routine = RTN_FindByName(image, "WriteProcessMemory");
		if (RTN_Valid(routine)) {
			printf("Instrumenting %s\n", RTN_Name(routine).c_str());
			RTN_Open(routine);
			RTN_InsertCall(routine, 
				IPOINT_BEFORE, (AFUNPTR)save_bytes, 
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
				IARG_END
			);
			RTN_Close(routine);
		}

		routine = RTN_FindByName(image, "ResumeThread");
		if (RTN_Valid(routine)) {
			printf("Instrumenting %s\n", RTN_Name(routine).c_str());
			/* We don't actually care about anything here, it's just our signal to reconstruct the original file, dump it to disk */
			RTN_Open(routine);
			RTN_InsertCall(routine,
				IPOINT_BEFORE, (AFUNPTR)rebuild,
				IARG_ADDRINT, RTN_Name(routine).c_str(),
				IARG_END
			);
			RTN_Close(routine);
		}
	}
}

int main(int argc, char *argv[]) {
	PIN_InitSymbols();
	if (PIN_Init(argc, argv) != 0) {
		fprintf(stderr, "Write some nice usage here\n");
		return 1;
	}

	/* In order to unpack RunPe, we need: */
	/* 1: A new process created in suspended mode */
	/* 2: Mutliple writes in suspended process in order to insert the packed code */
	/* 3: Resuming the main thread */
	IMG_AddInstrumentFunction(instrument_image, NULL);
	PIN_StartProgram();

	/* Just for style */
	return 0; 
}