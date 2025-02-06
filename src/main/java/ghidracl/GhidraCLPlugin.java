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

import java.awt.BorderLayout;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.*;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.armedbear.lisp.Interpreter;
import org.armedbear.lisp.JavaObject;
import org.armedbear.lisp.Packages;
import org.armedbear.lisp.Symbol;
import org.armedbear.lisp.Package;
import org.armedbear.lisp.Function;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.GhidraRun;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

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
		action.setMenuBarData(new MenuData(new String[] { "Common Lisp", "Start Slynkx" }, "Slynk"));
		tool.addAction(action);
		log.info("setup complete");
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
				monitor.setMessage("Loading slynk");
				Interpreter.evaluate("(ql:quickload :slynk)");
				monitor.increment();
				
				// run the init file
				initCL();
				log.info("here!!!!");

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
	
	protected void initCL() throws IOException {
		InputStream initFileStream  = getClass().getResourceAsStream("/init.lisp");
		String initFile = new String(initFileStream.readAllBytes(), StandardCharsets.UTF_8);
		Interpreter.evaluate(initFile);
		Package gcl = Packages.findPackage("ghidra-cl");
		Symbol setCurrentProgram = gcl.findAccessibleSymbol("set-current-program");
		Function setCurrentProgramFunc = (Function)setCurrentProgram.getSymbolFunction();
		setCurrentProgramFunc.execute(new JavaObject(this.getCurrentProgram()));
	}
}
