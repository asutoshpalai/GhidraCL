/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidracl;

import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.armedbear.lisp.Function;
import org.armedbear.lisp.Interpreter;
import org.armedbear.lisp.JavaObject;
import org.armedbear.lisp.LispObject;
import org.armedbear.lisp.Package;
import org.armedbear.lisp.Packages;
import org.armedbear.lisp.Stream;
import org.armedbear.lisp.Symbol;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra Common Lisp",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Common Lisp for Ghidra.",
	description = "Common Lisp for Ghidra."
)
//@formatter:on
public class GhidraCLPlugin extends ProgramPlugin {

	private Logger log = LogManager.getLogger(GhidraCLPlugin.class);

	/**
	 * GhidraCLPlugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraCLPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();

		tool.execute(new Task("create ABCL instance", false, false, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				Interpreter.createDefaultInstance(null);
			}
		});

		setupActions();

	}

	private void setupActions() {
		DockingAction action;

		// add menu action for Common Lisp->Start Slynk
		action = new DockingAction("Start Slynk", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				startSlynk();
			}
		};
		action.setEnabled(true);
		action.setMenuBarData(new MenuData(new String[] { "Common Lisp", "Start Slynk" }));
		tool.addAction(action);

		log.info("setup complete");
	}

	/*
	 * Add this to the end of setupActions during dev to automate the manual steps of
	 * connecting emacs to slync. You need to open emacs and run the manual steps at least
	 * once for this to work.
	 */
	private void macosDev() {
		// add menu action for Common Lisp->Reload init
		// for dev
		DockingAction action = new DockingAction("Reload Init", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				initCL();
			}
		};
		action.setEnabled(true);
		action.setMenuBarData(new MenuData(new String[] { "Common Lisp", "Reload Init" }));
		tool.addAction(action);

		startSlynk();

		String script = "tell application \"Emacs\" to activate\n" +
						 "tell application \"System Events\"\n" +
						 "  keystroke \"x\" using {option down}\n" +
						 "  keystroke \"sly-connect\"\n" +
						 "  keystroke return\n" +
						 "  keystroke return\n" +
						 "  keystroke return\n" +
						 "end tell";

		try {
			Process process = new ProcessBuilder("osascript", "-e", script).start();
			// Handle process input/output if needed
			int exitCode = process.waitFor();
			if (exitCode == 0) {
				log.info("AppleScript executed successfully.");
			} else {
				log.error("AppleScript execution failed with code: " + exitCode);
			}
		} catch (IOException | InterruptedException e) {
			Msg.showError(GhidraCLPlugin.class, null, "Activating emcas", "failed to activate emacs", e);
		}
	}

	/**
	 * Callback for Common Lisp->Start Slynk menu option
	 */
	protected void startSlynk() {
		TaskLauncher.launchModal("Starting Slynk", monitor -> {
			try {
				monitor.setMaximum(5);
				monitor.setMessage("Loading abcl contrib");
				Interpreter.evaluate("(require :abcl-contrib)");
				monitor.increment();

				monitor.setMessage("Loading abcl quicklisp");
				Interpreter.evaluate("(require :quicklisp-abcl)");
				monitor.increment();

				monitor.setMessage("Initializing ghidra-cl");
				initCL();
				monitor.increment();

				monitor.setMessage("Loading slynk");
				Interpreter.evaluate("(ql:quickload :slynk)");
				monitor.increment();

				monitor.setMessage("Starting slynk server");
				Interpreter.evaluate("(slynk:create-server :port 4008)");
				monitor.increment();

				Msg.showInfo(GhidraCLPlugin.class, null, "Start Slynk", "Slynk started at localhost:4008");
			} catch (Exception e) {
				Msg.showError(GhidraCLPlugin.class, null, "Starting Slynk", "failed to start slynk", e);
			}
		});
	}

	protected void initCL() {
		InputStream initFileInputStream  = getClass().getResourceAsStream("/init.lisp");
		if (initFileInputStream == null) {
			log.warn("there is no init CL file");
			return;
		}

		// run the init file
		// Hail https://stackoverflow.com/a/62745593
		LispObject LOAD_function = Symbol.LOAD.getSymbolFunction ();
		Stream initFileStream = new Stream (Symbol.SYSTEM_STREAM, initFileInputStream, Symbol.CHARACTER);
		LOAD_function.execute(initFileStream);

		// expose current program
		Package gcl = Packages.findPackage("GHIDRA-CL");

		Function setGLInstance = (Function)gcl.findAccessibleSymbol("SET-GHIDRA-CL-INSTANCE").
					getSymbolFunction();
		setGLInstance.execute(new JavaObject(this));
	}
}
