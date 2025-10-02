/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */  // Τυπική επικεφαλίδα πνευματικών δικαιωμάτων & άδειας χρήσης (MIT).

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */  // Περιγραφή: εργαλείο PIN ανεξάρτητο αρχιτεκτονικής για καταγραφή προσβάσεων μνήμης.

 #include <stdio.h>      // Χρήση της stdio για fprintf, FILE* κτλ.
 #include "pin.H"        // Κύριο header της βιβλιοθήκης Pin API.
 
 FILE* trace;            // Γενικός δείκτης σε αρχείο όπου θα γράφουμε το trace.
 
 /* --------------------- Συναρτήσεις καταγραφής ------------------------ */
 
 // Print a memory read record
 VOID RecordMemRead(VOID* ip, VOID* addr) { fprintf(trace, "%p: R %p\n", ip, addr); }
 // ^ Καταγράφει μία ανάγνωση μνήμης: τυπώνει "IP: R ADDRESS" στο αρχείο trace.
 
 // Print a memory write record
 VOID RecordMemWrite(VOID* ip, VOID* addr) { fprintf(trace, "%p: W %p\n", ip, addr); }
 // ^ Καταγράφει μία εγγραφή μνήμης: τυπώνει "IP: W ADDRESS".
 
 /* ------------- Instrumentation callback για κάθε instruction ---------- */
 
 // Is called for every instruction and instruments reads and writes
 VOID Instruction(INS ins, VOID* v)          // Callback που το Pin καλεί για ΚΑΘΕ instruction.
 {
     // Instruments memory accesses using a predicated call, i.e.
     // the instrumentation is called iff the instruction will actually be executed.
     //
     // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
     // prefixed instructions appear as predicated instructions in Pin.
     UINT32 memOperands = INS_MemoryOperandCount(ins);
     // ^ Παίρνουμε πόσοι memory operands υπάρχουν στο συγκεκριμένο instruction.
 
     // Iterate over each memory operand of the instruction.
     for (UINT32 memOp = 0; memOp < memOperands; memOp++)  // Βρόχος πάνω σε κάθε τελεστέο μνήμης.
     {
         if (INS_MemoryOperandIsRead(ins, memOp))          // Αν αυτός ο τελεστέος διαβάζεται...
         {
             // Εισάγουμε predicated call ΠΡΙΝ την εκτέλεση του instruction.
             // Θα καλέσει RecordMemRead μόνο αν η εντολή όντως εκτελεστεί (predicate αληθές).
             INS_InsertPredicatedCall(
                 ins,                                      // Η εντολή που οργανοθετούμε.
                 IPOINT_BEFORE,                            // Σημείο εισαγωγής: πριν την εκτέλεση.
                 (AFUNPTR)RecordMemRead,                   // Συνάρτηση που θα καλεστεί.
                 IARG_INST_PTR,                            // 1ο όρισμα προς RecordMemRead: IP της εντολής.
                 IARG_MEMORYOP_EA, memOp,                  // 2ο όρισμα: Effective Address του mem operand 'memOp'.
                 IARG_END);                                 // Τερματισμός λίστας ορισμάτων.
         }
         // Note that in some architectures a single memory operand can be
         // both read and written (for instance incl (%eax) on IA-32)
         // In that case we instrument it once for read and once for write.
         if (INS_MemoryOperandIsWritten(ins, memOp))       // Αν ο τελεστέος γράφεται...
         {
             // Αντίστοιχη predicated κλήση για εγγραφή μνήμης.
             INS_InsertPredicatedCall(
                 ins,                                      // Η ίδια εντολή.
                 IPOINT_BEFORE,                            // Πριν την εκτέλεση.
                 (AFUNPTR)RecordMemWrite,                  // Συνάρτηση καταγραφής εγγραφής.
                 IARG_INST_PTR,                            // 1ο όρισμα: IP.
                 IARG_MEMORYOP_EA, memOp,                  // 2ο όρισμα: Effective Address του mem operand.
                 IARG_END);                                 // Τέλος ορισμάτων.
         }
     }
 }
 
 /* ----------------------- Τερματισμός εργαλείου ----------------------- */
 
 VOID Fini(INT32 code, VOID* v)              // Callback που το Pin καλεί στο τέλος του προγράμματος.
 {
     fprintf(trace, "#eof\n");               // Γράφουμε έναν δείκτη τέλους αρχείου στο trace.
     fclose(trace);                          // Κλείνουμε το αρχείο καταγραφής.
 }
 
 /* ===================================================================== */
 /* Print Help Message                                                    */
 /* ===================================================================== */
 
 INT32 Usage()                               // Εμφάνιση μηνύματος βοήθειας όταν το PIN_Init αποτύχει.
 {
     PIN_ERROR("This Pintool prints a trace of memory addresses\n"
               + KNOB_BASE::StringKnobSummary() + "\n");   // Εξήγηση χρήσης + σύνοψη επιλογών γραμμής εντολών.
     return -1;                                            // Κωδικός σφάλματος.
 }
 
 /* ===================================================================== */
 /* Main                                                                  */
 /* ===================================================================== */
 
 int main(int argc, char* argv[])            // Κύρια συνάρτηση του εργαλείου PIN.
 {
     if (PIN_Init(argc, argv)) return Usage();
     // ^ Αρχικοποίηση του Pin με τα argv/argc. Αν επιστρέψει μηδέν → OK, αλλιώς δείξε Usage().
 
     trace = fopen("pinatrace.out", "w");    // Άνοιγμα αρχείου εξόδου για το trace (overwrite mode).
 
     INS_AddInstrumentFunction(Instruction, 0);
     // ^ Δηλώνουμε την callback 'Instruction' ώστε να καλείται για κάθε instruction.
 
     PIN_AddFiniFunction(Fini, 0);
     // ^ Δηλώνουμε την callback 'Fini' ώστε να κλείσουμε καθαρά στο τέλος.
 
     // Never returns
     PIN_StartProgram();
     // ^ Εκκινεί το target πρόγραμμα κάτω από τον έλεγχο του Pin και ΔΕΝ επιστρέφει ποτέ.
 
     return 0;                               // Απλά για πληρότητα· δεν φτάνουμε εδώ.
 }