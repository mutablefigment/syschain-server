project('syschain-sever', ['d'])

dub_exe = find_program('dub', required : false)
if not dub_exe.found()
    error('MESON_SKIP_TEST: Dub not found')
endif

if meson.get_compiler('d').get_id() == 'gcc'
    error('MESON_SKIP_TEST: can\'t build dependencies with GDC')
elif meson.get_compiler('d').get_id() == 'llvm'
    dc = 'ldc2'
elif meson.get_compiler('d').get_id() == 'dmd'
    dc = 'dmd'
endif

arch = host_machine.cpu_family()

if host_machine.system() == 'windows'
    # check if toolchain is 32bits
    sz = meson.get_compiler('d').sizeof('void*')
    if arch == 'x86' or sz == 4
        arch = 'x86_mscoff'
    endif
endif

# run_command(
#     'dub', 'run', 'dub-build-deep', '--yes', '--', 'vibe-d', '--compiler', dc, '--arch', arch,
#     check: true,
# )

# run_command(
#     'dub', 'run', 'dub-build-deep', '--yes', '--', 'botan', '--compiler', dc, '--arch', arch,
#     check: true,
# )

# run_command(
#     'dub', 'run', 'dub-build-deep', '--yes', '--', 'botan-math', '--compiler', dc, '--arch', arch,
#     check: true,
# )

vibed_dep = dependency('vibe-d', method: 'dub')
botan_dep = dependency('botan', method: 'dub')
botan_math_dep = dependency('botan-math', method: 'dub')

syschain_exe = executable('syschain-server', 'app.d', 'block.d', 'device.d', 'ServerInterface.d',
 dependencies: [vibed_dep, botan_dep, botan_math_dep])

