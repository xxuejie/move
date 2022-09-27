// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use criterion::{measurement::Measurement, Criterion};
use move_binary_format::{access::ModuleAccess, CompiledModule};
use move_compiler::{compiled_unit::AnnotatedCompiledUnit, shared::NumericalAddress, Compiler};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag, TypeTag},
    value::{MoveStruct, MoveValue},
};
use move_vm_runtime::move_vm::MoveVM;
use move_vm_test_utils::InMemoryStorage;
use move_vm_types::gas::UnmeteredGasMeter;
// use once_cell::sync::Lazy;
use std::path::Path;

/// Entry point for the bench, provide a function name to invoke in Module Bench in bench.move.
pub fn bench<M: Measurement + 'static>(c: &mut Criterion<M>, fun: &str) {
    let modules = compile_modules();
    let move_vm = MoveVM::new(move_stdlib::natives::all_natives(
        AccountAddress::from_hex_literal("0x1").unwrap(),
        move_stdlib::natives::GasParameters::zeros(),
    ))
    .unwrap();

    match fun {
        "basic_coin_transfer" => execute_basic_coin_transfer(c, &move_vm, modules),
        "swap" => execute_swap(c, &move_vm, modules),
        _ => panic!("Unknown fun: {}", fun),
    }
}

// Compile `bench.move` and its dependencies
fn compile_modules() -> Vec<CompiledModule> {
    let mut src_files = move_stdlib::move_stdlib_files();
    let examples_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("documentation")
        .join("examples")
        .join("experimental");
    src_files.push(
        examples_path
            .join("basic-coin")
            .join("sources")
            .join("BasicCoin.move")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    let coin_swap_path = examples_path.join("coin-swap").join("sources");
    src_files.push(
        coin_swap_path
            .join("GoldCoin.move")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    src_files.push(
        coin_swap_path
            .join("SilverCoin.move")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    src_files.push(
        coin_swap_path
            .join("PoolToken.move")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    src_files.push(
        coin_swap_path
            .join("CoinSwap.move")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    let mut named_addresses: Vec<(String, NumericalAddress)> =
        move_stdlib::move_stdlib_named_addresses()
            .into_iter()
            .collect();
    named_addresses.extend(
        [
            ("BasicCoin", "0xFF01"),
            ("GoldCoin", "0xFF02"),
            ("SilverCoin", "0xFF03"),
            ("PoolToken", "0xFF04"),
            ("CoinSwap", "0xFF05"),
        ]
        .iter()
        .map(|(name, addr)| {
            (
                name.to_string(),
                NumericalAddress::parse_str(addr).expect("parse_str"),
            )
        }),
    );
    let (_files, compiled_units) =
        Compiler::from_files(src_files, vec![], named_addresses.into_iter().collect())
            .build_and_report()
            .expect("Error compiling...");
    compiled_units
        .into_iter()
        .map(|unit| match unit {
            AnnotatedCompiledUnit::Module(annot_unit) => annot_unit.named_module.module,
            AnnotatedCompiledUnit::Script(_) => {
                panic!("Expected a module but received a script")
            }
        })
        .collect()
}

fn execute_basic_coin_transfer<M: Measurement + 'static>(
    c: &mut Criterion<M>,
    move_vm: &MoveVM,
    modules: Vec<CompiledModule>,
) {
    // establish running context
    let storage = InMemoryStorage::new();
    let module_address = AccountAddress::from_hex_literal("0xFF02").expect("sender");
    let mut session = move_vm.new_session(&storage);

    // TODO: we may want to use a real gas meter to make benchmarks more realistic.

    for module in modules {
        let mut mod_blob = vec![];
        module
            .serialize(&mut mod_blob)
            .expect("Module serialization error");
        session
            .publish_module(
                mod_blob,
                module.address().to_owned(),
                &mut UnmeteredGasMeter,
            )
            .expect("Module must load");
    }

    // module and function to call
    let module_id = ModuleId::new(module_address, Identifier::new("GoldCoin").unwrap());
    let transfer_fun = IdentStr::new("transfer").unwrap();

    // Deposit amounts to transfer first
    let mint_fun = IdentStr::new("setup_and_mint").unwrap();
    let alice = AccountAddress::from_hex_literal("0xEEEE").unwrap();
    let bob = AccountAddress::from_hex_literal("0xEECC").unwrap();

    {
        let args = vec![
            MoveValue::Signer(alice).simple_serialize().unwrap(),
            MoveValue::U64(u64::max_value()).simple_serialize().unwrap(),
        ];
        session
            .execute_function_bypass_visibility(
                &module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();

        let args = vec![
            MoveValue::Signer(bob).simple_serialize().unwrap(),
            MoveValue::U64(100).simple_serialize().unwrap(),
        ];
        session
            .execute_function_bypass_visibility(
                &module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();
    }

    let transfer_args: Vec<Vec<u8>> = vec![
        MoveValue::Signer(alice),
        MoveValue::Signer(bob),
        MoveValue::U64(1),
    ]
    .into_iter()
    .map(|v| v.simple_serialize().unwrap())
    .collect();

    // benchmark
    c.bench_function("basic_coin_transfer", |b| {
        b.iter(|| {
            session
                .execute_function_bypass_visibility(
                    &module_id,
                    transfer_fun,
                    vec![],
                    transfer_args.clone(),
                    &mut UnmeteredGasMeter,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "{:?}::{} failed with {:?}",
                        &module_id,
                        "transfer",
                        err.into_vm_status()
                    )
                })
        })
    });
}

fn execute_swap<M: Measurement + 'static>(
    c: &mut Criterion<M>,
    move_vm: &MoveVM,
    modules: Vec<CompiledModule>,
) {
    // establish running context
    let storage = InMemoryStorage::new();
    let coin_swap_address = AccountAddress::from_hex_literal("0xFF05").expect("sender");
    let mut session = move_vm.new_session(&storage);

    // TODO: we may want to use a real gas meter to make benchmarks more realistic.

    for module in modules {
        let mut mod_blob = vec![];
        module
            .serialize(&mut mod_blob)
            .expect("Module serialization error");
        session
            .publish_module(
                mod_blob,
                module.address().to_owned(),
                &mut UnmeteredGasMeter,
            )
            .expect("Module must load");
    }

    // Setup pool
    let coin_swap_module_id =
        ModuleId::new(coin_swap_address, Identifier::new("CoinSwap").unwrap());
    let pool_creator = AccountAddress::from_hex_literal("0xAAAA").unwrap();
    let alice = AccountAddress::from_hex_literal("0xEEEE").unwrap();
    let gold_module_address = AccountAddress::from_hex_literal("0xFF02").expect("sender");
    let gold_module_id = ModuleId::new(gold_module_address, Identifier::new("GoldCoin").unwrap());
    let silver_module_address = AccountAddress::from_hex_literal("0xFF03").expect("sender");
    let silver_module_id = ModuleId::new(
        silver_module_address,
        Identifier::new("SilverCoin").unwrap(),
    );
    let type_args = vec![
        TypeTag::Struct(StructTag {
            address: gold_module_address,
            module: Identifier::new("GoldCoin").unwrap(),
            name: Identifier::new("GoldCoin").unwrap(),
            type_params: vec![],
        }),
        TypeTag::Struct(StructTag {
            address: silver_module_address,
            module: Identifier::new("SilverCoin").unwrap(),
            name: Identifier::new("SilverCoin").unwrap(),
            type_params: vec![],
        }),
    ];

    {
        let mint_fun = IdentStr::new("setup_and_mint").unwrap();

        let args = vec![
            MoveValue::Signer(pool_creator).simple_serialize().unwrap(),
            MoveValue::U64(u64::max_value()).simple_serialize().unwrap(),
        ];

        session
            .execute_function_bypass_visibility(
                &gold_module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();

        let args = vec![
            MoveValue::Signer(alice).simple_serialize().unwrap(),
            MoveValue::U64(u64::max_value()).simple_serialize().unwrap(),
        ];

        session
            .execute_function_bypass_visibility(
                &gold_module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();

        let args = vec![
            MoveValue::Signer(pool_creator).simple_serialize().unwrap(),
            MoveValue::U64(u64::max_value()).simple_serialize().unwrap(),
        ];

        session
            .execute_function_bypass_visibility(
                &silver_module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();

        let args = vec![
            MoveValue::Signer(alice).simple_serialize().unwrap(),
            MoveValue::U64(0).simple_serialize().unwrap(),
        ];

        session
            .execute_function_bypass_visibility(
                &silver_module_id,
                mint_fun,
                vec![],
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();

        let create_pool_fun = IdentStr::new("create_pool").unwrap();
        let args = vec![
            MoveValue::Signer(coin_swap_address),
            MoveValue::Signer(pool_creator),
            MoveValue::U64(0xFFFFACFF00),
            MoveValue::U64(0x1212FFFF00),
            MoveValue::U64(0xFFAAFF00),
            MoveValue::Struct(MoveStruct::Runtime(vec![MoveValue::Bool(false)])),
            MoveValue::Struct(MoveStruct::Runtime(vec![MoveValue::Bool(false)])),
        ]
        .into_iter()
        .map(|v| v.simple_serialize().unwrap())
        .collect();

        session
            .execute_function_bypass_visibility(
                &coin_swap_module_id,
                create_pool_fun,
                type_args.clone(),
                args,
                &mut UnmeteredGasMeter,
            )
            .unwrap();
    }

    // module and function to call
    let swap_fun = IdentStr::new("coin1_to_coin2_swap_input").unwrap();

    let swap_args: Vec<Vec<u8>> = vec![
        MoveValue::Signer(coin_swap_address),
        MoveValue::Signer(alice),
        MoveValue::U64(5),
        MoveValue::Struct(MoveStruct::Runtime(vec![MoveValue::Bool(false)])),
        MoveValue::Struct(MoveStruct::Runtime(vec![MoveValue::Bool(false)])),
    ]
    .into_iter()
    .map(|v| v.simple_serialize().unwrap())
    .collect();

    // benchmark
    c.bench_function("swap", |b| {
        b.iter(|| {
            session
                .execute_function_bypass_visibility(
                    &coin_swap_module_id,
                    swap_fun,
                    type_args.clone(),
                    swap_args.clone(),
                    &mut UnmeteredGasMeter,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "{:?}::{} failed with {:?}",
                        &coin_swap_module_id,
                        "transfer",
                        err.into_vm_status()
                    )
                })
        })
    });
}
