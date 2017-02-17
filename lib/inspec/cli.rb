#!/usr/bin/env ruby
# encoding: utf-8
# Copyright 2015 Dominik Richter. All rights reserved.
# author: Dominik Richter
# author: Christoph Hartmann

require 'logger'
require 'thor'
require 'json'
require 'pp'
require 'utils/json_log'
require 'inspec/base_cli'
require 'inspec/plugins'
require 'inspec/runner_mock'
require 'inspec/env_printer'

class Inspec::InspecCLI < Inspec::BaseCLI # rubocop:disable Metrics/ClassLength
  class_option :log_level, aliases: :l, type: :string,
               desc: 'Set the log level: info (default), debug, warn, error'

  class_option :log_location, type: :string,
               desc: 'Location to send diagnostic log messages to. (default: STDOUT or STDERR)'

  class_option :diagnose, type: :boolean,
    desc: 'Show diagnostics (versions, configurations)'

  desc 'json PATH', 'read all tests in PATH and generate a JSON summary'
  option :output, aliases: :o, type: :string,
    desc: 'Save the created profile to a path'
  option :controls, type: :array,
    desc: 'A list of controls to include. Ignore all other tests.'
  profile_options
  def json(target)
    diagnose
    o = opts.dup
    configure_logger(o)
    o[:ignore_supports] = true
    o[:backend] = Inspec::Backend.create(target: 'mock://')

    profile = Inspec::Profile.for_target(target, o)
    dst = o[:output].to_s
    if dst.empty?
      puts JSON.dump(profile.info)
    else
      if File.exist? dst
        puts "----> updating #{dst}"
      else
        puts "----> creating #{dst}"
      end
      fdst = File.expand_path(dst)
      File.write(fdst, JSON.dump(profile.info))
    end
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'check PATH', 'verify all tests at the specified PATH'
  option :format, type: :string
  profile_options
  def check(path) # rubocop:disable Metrics/AbcSize
    diagnose
    o = opts.dup
    configure_logger(o)
    o[:ignore_supports] = true # we check for integrity only
    o[:backend] = Inspec::Backend.create(target: 'mock://')

    # run check
    profile = Inspec::Profile.for_target(path, o)
    result = profile.check

    if opts['format'] == 'json'
      puts JSON.generate(result)
    else
      %w{location profile controls timestamp valid}.each do |item|
        puts format('%-12s %s', item.to_s.capitalize + ':',
                    mark_text(result[:summary][item.to_sym]))
      end
      puts

      if result[:errors].empty? and result[:warnings].empty?
        puts 'No errors or warnings'
      else
        red    = "\033[31m"
        yellow = "\033[33m"
        rst    = "\033[0m"

        item_msg = lambda { |item|
          pos = [item[:file], item[:line], item[:column]].compact.join(':')
          pos.empty? ? item[:msg] : pos + ': ' + item[:msg]
        }
        result[:errors].each do |item|
          puts "#{red}  ✖  #{item_msg.call(item)}#{rst}"
        end
        result[:warnings].each do |item|
          puts "#{yellow}  !  #{item_msg.call(item)}#{rst}"
        end

        puts
        puts format('Summary:     %s%d errors%s, %s%d warnings%s',
                    red, result[:errors].length, rst,
                    yellow, result[:warnings].length, rst)
      end
    end
    exit 1 unless result[:summary][:valid]
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'vendor PATH', 'Download all dependencies and generate a lockfile in a `vendor` directory'
  option :overwrite, type: :boolean, default: false,
    desc: 'Overwrite existing vendored dependencies and lockfile.'
  def vendor(path = nil) # rubocop:disable Metrics/AbcSize
    o = opts.dup

    path.nil? ? path = Pathname.new(Dir.pwd) : path = Pathname.new(path)
    cache_path = path.join('vendor')
    inspec_lock = path.join('inspec.lock')

    if (cache_path.exist? || inspec_lock.exist?) && !opts[:overwrite]
      puts 'Profile is already vendored. Use --overwrite.'
      return false
    end

    # remove existing
    FileUtils.rm_rf(cache_path) if cache_path.exist?
    File.delete(inspec_lock) if inspec_lock.exist?

    puts "Vendor dependencies of #{path} into #{cache_path}"
    o[:logger] = Logger.new(STDOUT)
    o[:logger].level = get_log_level(o.log_level)
    o[:cache] = Inspec::Cache.new(cache_path.to_s)
    o[:backend] = Inspec::Backend.create(target: 'mock://')
    configure_logger(o)

    # vendor dependencies and generate lockfile
    profile = Inspec::Profile.for_target(path.to_s, o)
    lockfile = profile.generate_lockfile
    File.write(inspec_lock, lockfile.to_yaml)
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'archive PATH', 'archive a profile to tar.gz (default) or zip'
  profile_options
  option :output, aliases: :o, type: :string,
    desc: 'Save the archive to a path'
  option :zip, type: :boolean, default: false,
    desc: 'Generates a zip archive.'
  option :tar, type: :boolean, default: false,
    desc: 'Generates a tar.gz archive.'
  option :overwrite, type: :boolean, default: false,
    desc: 'Overwrite existing archive.'
  option :ignore_errors, type: :boolean, default: false,
    desc: 'Ignore profile warnings.'
  def archive(path)
    diagnose

    o = opts.dup
    o[:logger] = Logger.new(STDOUT)
    o[:logger].level = get_log_level(o.log_level)
    o[:backend] = Inspec::Backend.create(target: 'mock://')

    profile = Inspec::Profile.for_target(path, o)
    result = profile.check

    if result && !opts[:ignore_errors] == false
      o[:logger].info 'Profile check failed. Please fix the profile before generating an archive.'
      return exit 1
    end

    # generate archive
    exit 1 unless profile.archive(opts)
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'exec PATHS', 'run all test files at the specified PATH.'
  exec_options
  def exec(*targets)
    diagnose
    configure_logger(opts)
    o = opts.dup

    # run tests
    run_tests(targets, o)
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'detect', 'detect the target OS'
  target_options
  option :format, type: :string
  def detect
    o = opts.dup
    o[:command] = 'os.params'
    (_, res) = run_command(o)
    if opts['format'] == 'json'
      puts res.to_json
    else
      headline('Operating System Details')
      %w{name family release arch}.each { |item|
        puts format('%-10s %s', item.to_s.capitalize + ':',
                    mark_text(res[item.to_sym]))
      }
    end
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'shell', 'open an interactive debugging shell'
  target_options
  option :command, aliases: :c,
    desc: 'A single command string to run instead of launching the shell'
  option :format, type: :string, default: nil, hide: true,
    desc: 'Which formatter to use: cli, progress, documentation, json, json-min, junit'
  def shell_func
    diagnose
    o = opts.dup

    json_output = ['json', 'json-min'].include?(opts['format'])
    log_device = json_output ? nil : STDOUT
    o[:logger] = Logger.new(log_device)
    o[:logger].level = get_log_level(o.log_level)

    if o[:command].nil?
      runner = Inspec::Runner.new(o)
      return Inspec::Shell.new(runner).start
    end

    run_type, res = run_command(o)
    exit res unless run_type == :ruby_eval

    # No InSpec tests - just print evaluation output.
    res = (res.respond_to?(:to_json) ? res.to_json : JSON.dump(res)) if json_output
    puts res
    exit 0
  rescue RuntimeError, Train::UserError => e
    $stderr.puts e.message
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'env', 'Output shell-appropriate completion configuration'
  def env(shell = nil)
    p = Inspec::EnvPrinter.new(self.class, shell)
    p.print_and_exit!
  rescue StandardError => e
    pretty_handle_exception(e)
  end

  desc 'status', 'Provides status about the current state'
  def status(shell = nil)
    current_state = ColdStartState.new
    until current_state.finished?
      current_state.prompt!
      current_state = current_state.resolve_with_context(self)
    end

  rescue StandardError => e
    pretty_handle_exception(e)
  end

  require 'tty-prompt'

  class MenuState
    def initialize(options = {})
      @options = options
    end

    attr_reader :options

    def finished?
      false
    end

    def prompt!
      raise "Implement this method in class: #{self.class}"
    end

    def resolve_with_context(context)
      raise "Implement this method in class: #{self.class}"
    end
  end

  class ColdStartState < MenuState
    def prompt!
      puts "Ohai! I'm Inspec (#{Inspec::VERSION}). I can help you ensure this system or another one is compliant."
    end

    def resolve_with_context(context)
      if not Dir['*/inspec.yml'].empty?
        ProfilesPresentState.new
      else
        NoProfilesPresentState.new
      end
    end
  end

  class NoProfilesPresentState
    def options
      { "Initialize a new profile." => :init,
        "Help! What are all these commands and flags?" => :help,
        "Quit! Stop this right this moment" => :quit }
    end

    def prompt!
      require 'tty-prompt'
      puts %{\n  ---------------------------------------------------------------\n  No profiles were found locally.\n  ---------------------------------------------------------------}
      prompt = TTY::Prompt.new
      # selected_profile = prompt.select("Select a profile to check, execute, or (or quit)",profiles_with_controls + quit_option)
      @result = prompt.select("What would you like to do?",options)
    end

    def resolve_with_context(context)
      future_states[@result].call
    end

    def future_states
      { init: -> { InitState.new },
        help: -> { HelpState.new },
        quit: -> { FinishedState.new } }
    end

    def finished?
      false
    end
  end

  class FinishedState
    def finished?
      true
    end

    def prompt! ; end

    def resolve_with_context(context)
      # noop
    end
  end

  class InitState
    def finished?
      false
    end

    def proposed_default
      require 'tubular-faker'
      TubularFaker.company.gsub(' ','-')
    end

    def prompt!
      prompt = TTY::Prompt.new

      @result = prompt.ask("What would you like to name the profile?", default: proposed_default)
      # TODO: execute the `init profile NAME`
      # TODO: a default does not allow for a simple exit
      # TODO: consider mangling the CTRL+C exit to be a quit and not a stack trace.
      #   rescue SystemExit, Interrupt
    end

    def resolve_with_context(context)
      if @result && !@result.empty?
        InitProfileState.new(name: @result)
      else
        FinishedState.new
      end
    end
  end

  class InitProfileState
    def initialize(options)
      @options = options
    end

    attr_reader :options

    def prompt!
      # noop
      puts "Building you a profile named: #{options[:name]}"
    end

    def finished?
      false
    end

    def resolve_with_context(context)
      context.init 'profile', options[:name]
      # TODO: It could also react to the result of the operation. Try to verify its work. This doesn't have to be the end.
      CheckProfileState.new name: options[:name]
    end
  end

  class HelpState
    def initialize(options = {})
      @options = options
    end

    attr_reader :options

    def prompt!

    end

    def finished?
      false
    end

    def resolve_with_context(context)
      puts context.help
      FinishedState.new
    end

  end

  class CheckProfileState
    def initialize(options)
      @options = options
    end

    attr_reader :options

    def prompt!
      puts "Checking your profile!"
    end

    def finished?
      false
    end

    def resolve_with_context(context)
      context.check options[:name]
      ProfileActionState.new name: options[:name]
    end
  end

  class ProfilesPresentState < MenuState
    def profiles_with_controls
      profiles = Dir['*/inspec.yml'].map do |path|
        yaml = YAML.load_file(path.to_s)
        yaml.to_hash
      end
    end

    def profile_with_controls_title
      'Profiles and Controls'
    end

    def menu_items
      items = {}
      profiles_with_controls.each do |profile|
        menu_name = "#{profile['name']} (v #{profile['version']})"
        items[menu_name] = profile['name']
      end
      items['quit'] = :quit
      items
    end

    def prompt!
      prompt = TTY::Prompt.new
      @result = prompt.select("Select a profile or (or quit)",menu_items)
    end

    def resolve_with_context(context)
      if @result == :quit
        FinishedState.new
      else
        ProfileActionState.new name: @result
      end
    end
  end

  class ProfileActionState < MenuState
    def available_actions_for_profile
      { 'check' => :check,
        'execute' => :exec,
        'archive' => :archive }
    end

    def prompt!
      prompt = TTY::Prompt.new
      @result = prompt.select("Action",available_actions_for_profile)
    end

    def resolve_with_context(context)
      puts %{Executing: inspec #{@result} #{options[:name]}\n\n}
      context.send(@result,options[:name])
      self
    end
  end

  desc 'version', 'prints the version of this tool'
  def version
    puts Inspec::VERSION
  end

  private

  def run_command(opts)
    require 'pry' ; binding.pry
    runner = Inspec::Runner.new(opts)
    res = runner.eval_with_virtual_profile(opts[:command])
    runner.load

    return :ruby_eval, res if runner.all_rules.empty?
    return :rspec_run, runner.run_tests # rubocop:disable Style/RedundantReturn
  end
end

# Load all plugins on startup
ctl = Inspec::PluginCtl.new
ctl.list.each { |x| ctl.load(x) }

# load CLI plugins before the Inspec CLI has been started
Inspec::Plugins::CLI.subcommands.each { |_subcommand, params|
  Inspec::InspecCLI.register(
    params[:klass],
    params[:subcommand_name],
    params[:usage],
    params[:description],
    params[:options],
  )
}
