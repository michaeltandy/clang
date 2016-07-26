//=== VariadicChecker.cpp - Variadic argument usage checker-----*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This files defines VariadicChecker, a builtin checker that checks for
// mistakes using stdarg.h
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

struct VaListState {
private:
  enum Lifecycle { Started, Ended } L;
  VaListState(Lifecycle lc) : L(lc) { }

public:
  bool isStarted() const { return L == Started; }
  bool isEnded() const { return L == Ended; }

  static VaListState getStarted() { return VaListState(Started); }
  static VaListState getEnded() { return VaListState(Ended); }

  bool operator==(const VaListState &X) const {
    return L == X.L;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(L);
  }
};


class VariadicChecker : public Checker<check::PostCall,
										check::PreCall> {
  CallDescription VaStart;
  CallDescription VaEnd;

public:
  VariadicChecker();

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // End anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(VaListMap, const MemRegion *, VaListState)

VariadicChecker::VariadicChecker()
    : VaStart("__builtin_va_start"), VaEnd("__builtin_va_end") {

}

void VariadicChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
	if (Call.isCalled(VaStart)) {
		ProgramStateRef state = C.getState();
		llvm::outs() << "\n\nVaStart checkPostCall:\n";
		//state->dump();

		const ImplicitCastExpr *implicitCastVaList = cast<ImplicitCastExpr>(Call.getArgExpr(0));
		llvm::outs() << "implicitCastVaList:\n";
		implicitCastVaList->dump(llvm::outs());

		SVal vaListSVal = state->getSVal(implicitCastVaList, C.getLocationContext());
		llvm::outs() << "vaListSVal:\n";
		vaListSVal.dumpToStream(llvm::outs());

		const MemRegion *vaListRegion = vaListSVal.getAsRegion();
		llvm::outs() << "\nvaListRegion: " << (const void*)vaListRegion << "\n";
		vaListRegion->dumpToStream(llvm::outs());

		/*if (vaListSVal.getAsSymbol()) llvm::outs() << "getAsSymbol!\n";
		if (vaListSVal.getAsLocSymbol()) llvm::outs() << "getAsLocSymbol!\n";
		if (vaListSVal.getAsRegion()) llvm::outs() << "getAsRegion!\n";
		if (vaListSVal.getLocSymbolInBase()) llvm::outs() << "getLocSymbolInBase!\n";
		if (vaListSVal.getAsSymExpr()) llvm::outs() << "getAsSymExpr!\n";
		if (vaListSVal.getAsSymbolicExpression()) llvm::outs() << "getAsSymbolicExpression!\n";
		if (vaListSVal.getAsFunctionDecl()) llvm::outs() << "getAsFunctionDecl!\n";*/

		state = state->set<VaListMap>(vaListRegion, VaListState::getStarted());
		C.addTransition(state);
	}
}

void VariadicChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
	if (Call.isCalled(VaEnd)) {
		ProgramStateRef state = C.getState();
		llvm::outs() << "\n\n\n\nVaEnd checkPreCall:\n";
		//state->dump();

		const ImplicitCastExpr *implicitCastVaList = cast<ImplicitCastExpr>(Call.getArgExpr(0));
		llvm::outs() << "implicitCastVaList:\n";
		implicitCastVaList->dump(llvm::outs());

		SVal vaListSVal = state->getSVal(implicitCastVaList, C.getLocationContext());
		llvm::outs() << "vaListSVal:\n";
		vaListSVal.dumpToStream(llvm::outs());

		const MemRegion *vaListRegion = vaListSVal.getAsRegion();
		llvm::outs() << "\nvaListRegion: " << (const void*)vaListRegion << "\n";
		vaListRegion->dumpToStream(llvm::outs());

		const VaListState *vaListState = state->get<VaListMap>(vaListRegion);
		if (vaListState == 0) {
			llvm::outs() << "\n vaListState: Null\n";
		} else if (vaListState->isStarted()) {
			llvm::outs() << "\n vaListState: Started\n";
		} else if (vaListState->isEnded()) {
			llvm::outs() << "\n vaListState: Ended\n";
		} else {
			llvm::outs() << "\n vaListState: Confusing\n";
		}

		state = state->set<VaListMap>(vaListRegion, VaListState::getEnded());
		C.addTransition(state);
	}
}

void ento::registerVariadicChecker(CheckerManager &mgr) {
  mgr.registerChecker<VariadicChecker>();
}
