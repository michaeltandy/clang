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
										check::PreCall,
										check::PreStmt<Stmt>> {
  CallDescription VaStart;
  CallDescription VaEnd;

public:
  VariadicChecker();

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const Stmt *CE, CheckerContext &C) const;

private:
  mutable std::unique_ptr<BuiltinBug> doubleStartBug;
  void initDoubleStartBug() const;
  mutable std::unique_ptr<BuiltinBug> doubleEndBug;
  void initDoubleEndBug() const;
  mutable std::unique_ptr<BuiltinBug> endWithoutStartBug;
  void initEndWithoutStartBug() const;
  mutable std::unique_ptr<BuiltinBug> getWhenNotStartedBug;
  void initGetWhenNotStartedBug() const;


};

} // End anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(VaListMap, const MemRegion *, VaListState)

VariadicChecker::VariadicChecker()
    : VaStart("__builtin_va_start"), VaEnd("__builtin_va_end") {

}

void VariadicChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
	if (Call.isCalled(VaStart)) {
		ProgramStateRef state = C.getState();
		//llvm::outs() << "\n\nVaStart checkPostCall:\n";
		//state->dump();

		const ImplicitCastExpr *implicitCastVaList = cast<ImplicitCastExpr>(Call.getArgExpr(0));
		//llvm::outs() << "implicitCastVaList:\n";
		//implicitCastVaList->dump(llvm::outs());

		SVal vaListSVal = state->getSVal(implicitCastVaList, C.getLocationContext());
		//llvm::outs() << "vaListSVal:\n";
		//vaListSVal.dumpToStream(llvm::outs());

		const MemRegion *vaListRegion = vaListSVal.getAsRegion();
		//llvm::outs() << "\nvaListRegion: " << (const void*)vaListRegion << "\n";
		//vaListRegion->dumpToStream(llvm::outs());

		/*if (vaListSVal.getAsSymbol()) llvm::outs() << "getAsSymbol!\n";
		if (vaListSVal.getAsLocSymbol()) llvm::outs() << "getAsLocSymbol!\n";
		if (vaListSVal.getAsRegion()) llvm::outs() << "getAsRegion!\n";
		if (vaListSVal.getLocSymbolInBase()) llvm::outs() << "getLocSymbolInBase!\n";
		if (vaListSVal.getAsSymExpr()) llvm::outs() << "getAsSymExpr!\n";
		if (vaListSVal.getAsSymbolicExpression()) llvm::outs() << "getAsSymbolicExpression!\n";
		if (vaListSVal.getAsFunctionDecl()) llvm::outs() << "getAsFunctionDecl!\n";*/

		const VaListState *vaListState = state->get<VaListMap>(vaListRegion);
		if (vaListState!=0 && vaListState->isStarted()) {
			initDoubleStartBug();
			ExplodedNode *N = C.generateNonFatalErrorNode();
			auto R = llvm::make_unique<BugReport>(*doubleStartBug, doubleStartBug->getDescription(), N);
				  R->addRange(Call.getSourceRange());
				  C.emitReport(std::move(R));
		}

		state = state->set<VaListMap>(vaListRegion, VaListState::getStarted());
		C.addTransition(state);
	}
}

void VariadicChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
	if (Call.isCalled(VaEnd)) {
		ProgramStateRef state = C.getState();
		//llvm::outs() << "\n\n\n\nVaEnd checkPreCall:\n";
		//state->dump();

		const ImplicitCastExpr *implicitCastVaList = cast<ImplicitCastExpr>(Call.getArgExpr(0));
		//llvm::outs() << "implicitCastVaList:\n";
		//implicitCastVaList->dump(llvm::outs());

		SVal vaListSVal = state->getSVal(implicitCastVaList, C.getLocationContext());
		//llvm::outs() << "vaListSVal:\n";
		//vaListSVal.dumpToStream(llvm::outs());

		const MemRegion *vaListRegion = vaListSVal.getAsRegion();
		//llvm::outs() << "\nvaListRegion: " << (const void*)vaListRegion << "\n";
		//vaListRegion->dumpToStream(llvm::outs());

		const VaListState *vaListState = state->get<VaListMap>(vaListRegion);
		if (vaListState == 0) {
			initEndWithoutStartBug();
			ExplodedNode *N = C.generateNonFatalErrorNode();
			auto R = llvm::make_unique<BugReport>(*endWithoutStartBug, endWithoutStartBug->getDescription(), N);
				  R->addRange(Call.getSourceRange());
				  C.emitReport(std::move(R));
		} else if (vaListState->isEnded()) {
			initDoubleEndBug();
			ExplodedNode *N = C.generateNonFatalErrorNode();
			auto R = llvm::make_unique<BugReport>(*doubleEndBug, doubleEndBug->getDescription(), N);
				  R->addRange(Call.getSourceRange());
				  C.emitReport(std::move(R));
		}

		state = state->set<VaListMap>(vaListRegion, VaListState::getEnded());
		C.addTransition(state);
	}
}

void VariadicChecker::checkPreStmt(const Stmt *S, CheckerContext &C) const {
  if (S->getStmtClass() != Stmt::VAArgExprClass)
    return;

  ProgramStateRef state = C.getState();
  const VAArgExpr *VAE = cast<VAArgExpr>(S);

  llvm::outs() << "\n\nVAArgExpr:\n";
  VAE->dump(llvm::outs());

  // Revisit - are there alternatives to these options?
  assert(!VAE->isMicrosoftABI());
  assert(C.getASTContext().getBuiltinVaListType()->isArrayType());
  assert(isa<ImplicitCastExpr>(VAE->getSubExpr()));
  const ImplicitCastExpr *implicitCastVaList = cast<ImplicitCastExpr>(VAE->getSubExpr());

  SVal vaListSVal = state->getSVal(implicitCastVaList, C.getLocationContext());
  const MemRegion *vaListRegion = vaListSVal.getAsRegion();
  llvm::outs() << "\nvaListRegion: " << (const void*)vaListRegion << "\n";
  vaListRegion->dumpToStream(llvm::outs());

  const VaListState *vaListState = state->get<VaListMap>(vaListRegion);
  if (vaListState == 0 || vaListState->isEnded()) {
	  initGetWhenNotStartedBug();
	  ExplodedNode *N = C.generateNonFatalErrorNode();
	  auto R = llvm::make_unique<BugReport>(*getWhenNotStartedBug, getWhenNotStartedBug->getDescription(), N);
	  	  R->addRange(S->getSourceRange());
	  	  C.emitReport(std::move(R));
	  return;
  }
  assert(vaListState->isStarted());

}

void VariadicChecker::initDoubleStartBug() const {
	if (!doubleStartBug) {
		doubleStartBug.reset(
	        new BuiltinBug(this, "va_start when already started",
	               "va_start should not be invoked twice "
	               "unless there's a call to va_end in between."));
	}
}

void VariadicChecker::initDoubleEndBug() const {
	if (!doubleEndBug) {
		doubleEndBug.reset(
	        new BuiltinBug(this, "va_end called more than once",
	               "va_end should only be invoked once for each "
	               "call to va_start or va_copy."));
	}
}

void VariadicChecker::initEndWithoutStartBug() const {
	if (!endWithoutStartBug) {
		endWithoutStartBug.reset(
	        new BuiltinBug(this, "va_end called without va_start",
	               "va_end should only be invoked for variables "
	               "first populated by va_start or va_copy."));
	}
}

void VariadicChecker::initGetWhenNotStartedBug() const {
	if (!getWhenNotStartedBug) {
		getWhenNotStartedBug.reset(
	        new BuiltinBug(this, "va_arg called before va_start or after va_end",
	               "va_arg should only be invoked with a parameter "
	               "initialised by va_start or va_copy, "
	        	   "and not yet cleaned up by va_end."));
	}
}

void ento::registerVariadicChecker(CheckerManager &mgr) {
  mgr.registerChecker<VariadicChecker>();
}
