import { $ } from "bun";

for await (let line of $`echo "Hello World!"`.lines()) {
  console.log(line); // Hello World!
}

for (let char of "👨‍👩‍👧‍👦") {
  console.log(char);
}

console.log(Bun.version, Bun.revision, Bun.which("ls"));

const currentFile = import.meta.url;
Bun.openInEditor(currentFile);

await Bun.sleep(20_000);

// const childProc = Bun.spawn(["bun", "child.ts"], {
//   ipc(message, childProc) {
//     console.log("Message from child:", message);
//     /**
//      * The message received from the sub process
//      **/
//     childProc.send("Respond to child");
//   },
// });

// childProc.send("I am your father"); // The parent can send messages to the child as well
